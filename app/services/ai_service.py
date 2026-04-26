"""AI analysis service — supports Gemini (Vertex AI) and Claude (Anthropic)."""

import base64
import json
import logging

from app.config import settings
from app.models.threat import Threat
from app.models.ai_analysis import AIAnalysis
from app.services.storage_service import download_file

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """
You are a cybersecurity threat analyst for SQB Bank in Uzbekistan.
You analyze SMS and Telegram messages that were flagged as dangerous by
the SafeTalk on-device ML model (riskScore >= 70).

Your job is to provide a deep analysis of each threat for the bank's
security team. The messages are primarily in Uzbek (Latin script) and
Russian (Cyrillic).

When a screenshot of the suspicious website is provided, analyze it carefully:
- Does the site visually impersonate SQB Bank or any Uzbek financial institution?
- Are there login forms, card number inputs, or OTP fields?
- Does the branding, logo, or color scheme mimic a legitimate bank?
- Are there urgency cues ("Sizning kartangiz bloklandi!", "Tezda kiriting!")?
- Is there any grammatical or visual inconsistency suggesting a fake site?
- Does the URL in the address bar differ from the legitimate domain?

Analyze the threat and respond with ONLY a JSON object (no markdown,
no backticks, no preamble):

{
  "severity_assessment": "critical|high|medium|low",
  "threat_type": "credential_phishing|malware_distribution|social_engineering|otp_harvesting|brand_impersonation|prize_scam|curiosity_lure|unknown",
  "analysis_text": "Your detailed natural-language analysis in English. Explain what the attacker is trying to do, what technique they're using, and why it's dangerous. If a screenshot was provided, describe what the website looks like and why it is or isn't a phishing site.",
  "recommended_actions": ["action1", "action2"],
  "ioc_indicators": {
    "urls": ["extracted URLs"],
    "domains": ["extracted domains"],
    "phone_numbers": ["extracted phone numbers"],
    "file_hashes": [],
    "keywords": ["key scam trigger words found"]
  },
  "visual_analysis": {
    "is_phishing_site": true,
    "impersonated_brand": "SQB Bank / UzCard / Humo / etc or null",
    "has_login_form": true,
    "has_card_input": false,
    "visual_similarity_score": 85,
    "suspicious_elements": ["fake logo", "mismatched URL", "urgency text"]
  },
  "similar_pattern_description": "Describe if this matches known attack patterns (e.g., 'Classic Uzbek bank card blocking scam targeting UzCard/Humo users')",
  "confidence_score": 85
}
"""


def _build_user_message_text(threat: Threat, additional_context: str | None = None) -> str:
    """Build the text portion of the user message from threat data."""
    text = f"""
Analyze this flagged message:

Source: {threat.source.value}
Sender: {threat.sender_name or "Unknown"}
Source App: {threat.source_app or "Unknown"}
Risk Score (device ML): {threat.risk_score}/100
Device Label: {threat.label.value}
Device Reasons: {', '.join(threat.reasons or [])}
Detected URL: {threat.detected_url or "None"}
Detected File: {threat.detected_file_name or "None"} ({threat.detected_file_type or "N/A"})
Auto Tags: {', '.join(threat.auto_tags or [])}
Message Text (truncated): {threat.message_truncated or "[empty]"}
"""
    if additional_context:
        text += f"\nAdditional analyst context: {additional_context}"
    return text


def _load_screenshot(threat: Threat) -> tuple[bytes | None, str]:
    """Try to load screenshot bytes. Returns (bytes, extra_text)."""
    if not threat.screenshot_key:
        return None, ""
    try:
        data = download_file(threat.screenshot_key)
        logger.info(f"Including screenshot ({len(data)} bytes) in AI analysis")
        return data, "\n\nA screenshot of the suspicious website is attached above. Please analyze it visually."
    except Exception as e:
        logger.warning(f"Could not load screenshot for AI analysis: {e}")
        return None, "\n\n(Screenshot was requested but could not be loaded.)"


async def _analyze_with_gemini(
    user_text: str,
    screenshot_bytes: bytes | None,
) -> str:
    """Call Gemini REST API directly (no gRPC / no native deps)."""
    import aiohttp

    api_key = settings.GEMINI_API_KEY
    model = settings.GEMINI_MODEL
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={api_key}"

    # Build parts
    parts: list[dict] = []

    if screenshot_bytes:
        parts.append({
            "inline_data": {
                "mime_type": "image/png",
                "data": base64.b64encode(screenshot_bytes).decode("utf-8"),
            }
        })

    parts.append({"text": user_text})

    payload = {
        "system_instruction": {
            "parts": [{"text": SYSTEM_PROMPT}]
        },
        "contents": [
            {"role": "user", "parts": parts}
        ],
        "generationConfig": {
            "maxOutputTokens": 2048,
            "temperature": 0.2,
        },
    }

    async with aiohttp.ClientSession() as session:
        async with session.post(url, json=payload) as resp:
            if resp.status != 200:
                error_text = await resp.text()
                raise RuntimeError(f"Gemini API error {resp.status}: {error_text}")
            data = await resp.json()

    return data["candidates"][0]["content"]["parts"][0]["text"]


async def _analyze_with_claude(
    user_text: str,
    screenshot_bytes: bytes | None,
) -> str:
    """Call Claude via Anthropic SDK and return the response text."""
    import anthropic

    content: list[dict] = []

    if screenshot_bytes:
        screenshot_b64 = base64.b64encode(screenshot_bytes).decode("utf-8")
        content.append({
            "type": "image",
            "source": {
                "type": "base64",
                "media_type": "image/png",
                "data": screenshot_b64,
            },
        })

    content.append({"type": "text", "text": user_text})

    client = anthropic.Anthropic(api_key=settings.ANTHROPIC_API_KEY)

    response = client.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=1500,
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": content}],
    )

    return response.content[0].text


async def analyze_threat_with_ai(
    threat: Threat,
    additional_context: str | None = None,
    requested_by: str = "",
) -> AIAnalysis:
    """Send threat data to AI for deep analysis and return an AIAnalysis record."""

    screenshot_bytes, screenshot_text = _load_screenshot(threat)
    user_text = _build_user_message_text(threat, additional_context) + screenshot_text

    provider = settings.AI_PROVIDER.lower()
    logger.info(f"Running AI analysis with provider: {provider}")

    if provider == "gemini":
        model_name = settings.GEMINI_MODEL
        response_text = await _analyze_with_gemini(user_text, screenshot_bytes)
    else:
        model_name = "claude-sonnet-4-20250514"
        response_text = await _analyze_with_claude(user_text, screenshot_bytes)

    # Parse JSON response
    clean = response_text.strip().removeprefix("```json").removesuffix("```").strip()
    parsed = json.loads(clean)

    analysis = AIAnalysis(
        threat_id=threat.id,
        severity_assessment=parsed.get("severity_assessment"),
        threat_type=parsed.get("threat_type"),
        analysis_text=parsed.get("analysis_text", ""),
        recommended_actions=parsed.get("recommended_actions", []),
        ioc_indicators=parsed.get("ioc_indicators"),
        similar_pattern_description=parsed.get("similar_pattern_description"),
        confidence_score=parsed.get("confidence_score"),
        model_used=model_name,
        requested_by=requested_by,
    )

    return analysis
