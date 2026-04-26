"""Seed 25+ realistic Uzbek threat records for the hackathon demo."""

import sys
import os
import asyncio
import hashlib
from datetime import datetime, timedelta

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import engine, Base, async_session_factory
from app.models.threat import Threat, ThreatSource, ThreatLabel, ThreatStatus
from app.models.device import Device
from app.models.admin_user import AdminUser, AdminRole
from app.models.ai_analysis import AIAnalysis
from app.models.scan_run import ScanRun, ScannerType, ScanRunStatus
from app.models.brand_asset import BrandAsset, BrandAssetType
from app.models.scanner_pattern import ScannerPattern
from app.services.tagging_service import apply_auto_tags
from app.services.auth_service import hash_password


async def seed():
    # Create tables
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with async_session_factory() as session:
        # Check if already seeded
        result = await session.execute(select(Threat).limit(1))
        if result.scalar_one_or_none():
            print("[seed_demo] Demo data already exists, skipping.")
            return

        # ── Ensure admin exists ─────────────────────────────────────
        result = await session.execute(
            select(AdminUser).where(AdminUser.email == "admin@sqb.uz")
        )
        admin = result.scalar_one_or_none()
        if not admin:
            admin = AdminUser(
                email="admin@sqb.uz",
                password_hash=hash_password("SafeTalk2026!"),
                full_name="SQB Admin",
                role=AdminRole.SUPER_ADMIN,
                is_active=True,
            )
            session.add(admin)
            await session.flush()

        # Check if analyst exists
        result = await session.execute(
            select(AdminUser).where(AdminUser.email == "analyst@sqb.uz")
        )
        analyst = result.scalar_one_or_none()
        if not analyst:
            analyst = AdminUser(
                email="analyst@sqb.uz",
                password_hash=hash_password("Analyst2026!"),
                full_name="Alisher Karimov",
                role=AdminRole.ANALYST,
                is_active=True,
            )
            session.add(analyst)
            await session.flush()

        # ── Create devices ──────────────────────────────────────────
        devices = []
        for i, dev_uuid in enumerate(["dev-001-uuid", "dev-002-uuid", "dev-003-uuid"]):
            d = Device(
                device_hash=hashlib.sha256(dev_uuid.encode()).hexdigest(),
                app_version="1.0",
                first_seen_at=datetime.utcnow() - timedelta(days=30 - i * 5),
                last_seen_at=datetime.utcnow() - timedelta(hours=i),
                total_threats_reported=0,
            )
            session.add(d)
            devices.append(d)
        await session.flush()

        now = datetime.utcnow()

        # ── THREATS DATA ────────────────────────────────────────────
        threats_data = [
            # ── 5 Phishing SMS (fake SQB card block) ────────────────
            {
                "source": ThreatSource.AUTO_SMS, "label": ThreatLabel.DANGEROUS,
                "message": "Sizning SQB kartangiz bloklandi. Tiklash uchun: https://sqb-login.xyz/verify",
                "risk": 95, "confidence": 92, "sender": "+998901234567",
                "url": "https://sqb-login.xyz/verify", "status": ThreatStatus.NEW,
                "reasons": ["Fishing havolasi aniqlandi", "Shubhali TLD (.xyz)"],
                "device_idx": 0, "days_ago": 0,
            },
            {
                "source": ThreatSource.AUTO_SMS, "label": ThreatLabel.DANGEROUS,
                "message": "Hurmatli mijoz, kartangiz 3 marta xato kiritilgani uchun bloklandi. https://sqb-secure.top/unlock",
                "risk": 91, "confidence": 89, "sender": "+998931112233",
                "url": "https://sqb-secure.top/unlock", "status": ThreatStatus.CONFIRMED,
                "reasons": ["Fishing havolasi", "Brend taqlidi"],
                "device_idx": 0, "days_ago": 2,
            },
            {
                "source": ThreatSource.AUTO_SMS, "label": ThreatLabel.DANGEROUS,
                "message": "SQB Bank: Kartangiz to'xtatildi. Qayta faollashtirish: https://bit.ly/sqb-card",
                "risk": 88, "confidence": 85, "sender": "SQBBank",
                "url": "https://bit.ly/sqb-card", "status": ThreatStatus.NEW,
                "reasons": ["URL qisqartiruvchi aniqlandi"],
                "device_idx": 1, "days_ago": 1,
            },
            {
                "source": ThreatSource.AUTO_SMS, "label": ThreatLabel.DANGEROUS,
                "message": "Karta bloklangan! Tiklash: https://uzcard-verify.club/login",
                "risk": 93, "confidence": 90, "sender": "+998712223344",
                "url": "https://uzcard-verify.club/login", "status": ThreatStatus.ACTIONED,
                "reasons": ["Shubhali TLD (.club)", "Login sahifa taqlidi"],
                "device_idx": 2, "days_ago": 5,
            },
            {
                "source": ThreatSource.AUTO_SMS, "label": ThreatLabel.DANGEROUS,
                "message": "Humo kartangiz xavf ostida. Tekshiring: https://humo-bank.xyz/secure",
                "risk": 90, "confidence": 87, "sender": "+998951234567",
                "url": "https://humo-bank.xyz/secure", "status": ThreatStatus.NEW,
                "reasons": ["Brend taqlidi (Humo)", "Shubhali TLD"],
                "device_idx": 0, "days_ago": 0,
            },

            # ── 5 Telegram APK distribution ──────────���──────────────
            {
                "source": ThreatSource.AUTO_TELEGRAM, "label": ThreatLabel.DANGEROUS,
                "message": "Bu senmi rasmda? \U0001f602 Ko'r: https://t.me/photosuz/app.apk",
                "risk": 97, "confidence": 95, "sender": "unknown_user",
                "url": "https://t.me/photosuz/app.apk", "status": ThreatStatus.CONFIRMED,
                "reasons": ["APK fayl aniqlandi", "Qiziquvchanlik tuzog'i"],
                "file_name": "app.apk", "file_type": "application/vnd.android.package-archive",
                "source_app": "Telegram", "device_idx": 0, "days_ago": 3,
            },
            {
                "source": ThreatSource.AUTO_TELEGRAM, "label": ThreatLabel.DANGEROUS,
                "message": "Yangi Telegram Premium tekin! Yuklab oling: premium_stars.apk",
                "risk": 94, "confidence": 91, "sender": "TelegramPremiumUZ",
                "url": None, "status": ThreatStatus.NEW,
                "reasons": ["Premium firibgarlik", "APK zararli dastur"],
                "file_name": "premium_stars.apk", "file_type": "application/vnd.android.package-archive",
                "source_app": "Telegram", "device_idx": 1, "days_ago": 1,
            },
            {
                "source": ThreatSource.AUTO_TELEGRAM, "label": ThreatLabel.DANGEROUS,
                "message": "Rasmga qara bu senmisan? \U0001f914 https://t.me/lookphotos_bot",
                "risk": 92, "confidence": 88, "sender": "photo_check_bot",
                "url": "https://t.me/lookphotos_bot", "status": ThreatStatus.NEW,
                "reasons": ["Qiziquvchanlik tuzog'i", "Telegram bot havolasi"],
                "file_name": "gallery_viewer.apk", "file_type": "application/vnd.android.package-archive",
                "source_app": "Telegram", "device_idx": 2, "days_ago": 4,
            },
            {
                "source": ThreatSource.AUTO_TELEGRAM, "label": ThreatLabel.DANGEROUS,
                "message": "GTA VI Uzbek versiyasi! Bepul yuklab olish: gta6_uz.apk",
                "risk": 89, "confidence": 86, "sender": "GamesUzBot",
                "url": None, "status": ThreatStatus.FALSE_POSITIVE,
                "reasons": ["APK tarqatish"],
                "file_name": "gta6_uz.apk", "file_type": "application/vnd.android.package-archive",
                "source_app": "Telegram", "device_idx": 1, "days_ago": 7,
            },
            {
                "source": ThreatSource.AUTO_TELEGRAM, "label": ThreatLabel.DANGEROUS,
                "message": "Video ko'rish uchun yangi player kerak: media_player.apk",
                "risk": 91, "confidence": 88, "sender": "VideoUZ_channel",
                "url": None, "status": ThreatStatus.NEW,
                "reasons": ["APK zararli dastur ehtimoli"],
                "file_name": "media_player.apk", "file_type": "application/vnd.android.package-archive",
                "source_app": "Telegram", "device_idx": 0, "days_ago": 2,
            },

            # ── 3 OTP harvesting ─────────────────���──────────────────
            {
                "source": ThreatSource.AUTO_SMS, "label": ThreatLabel.DANGEROUS,
                "message": "SQB xavfsizlik tizimi: Iltimos, SMS orqali kelgan kodni yuboring tasdiqlash uchun",
                "risk": 96, "confidence": 93, "sender": "+998901119988",
                "url": None, "status": ThreatStatus.CONFIRMED,
                "reasons": ["OTP so'rash aniqlandi"],
                "device_idx": 0, "days_ago": 1,
            },
            {
                "source": ThreatSource.AUTO_SMS, "label": ThreatLabel.DANGEROUS,
                "message": "Код подтверждения: Отправьте ваш OTP для завершения операции",
                "risk": 94, "confidence": 91, "sender": "+998941234567",
                "url": None, "status": ThreatStatus.NEW,
                "reasons": ["OTP yig'ish urinishi (ruscha)"],
                "device_idx": 1, "days_ago": 0,
            },
            {
                "source": ThreatSource.AUTO_SMS, "label": ThreatLabel.DANGEROUS,
                "message": "Payme tasdiqlash kodi keldi, iltimos kiriting: https://payme-confirm.xyz",
                "risk": 92, "confidence": 89, "sender": "+998900001122",
                "url": "https://payme-confirm.xyz", "status": ThreatStatus.NEW,
                "reasons": ["OTP fishing", "Brend taqlidi (Payme)"],
                "device_idx": 2, "days_ago": 3,
            },

            # ── 3 Telegram premium scam ─────────────────────────────
            {
                "source": ThreatSource.AUTO_TELEGRAM, "label": ThreatLabel.DANGEROUS,
                "message": "Telegram Stars tekin olish! Bepul premium 12 oy: https://tg-stars-free.icu/claim",
                "risk": 87, "confidence": 84, "sender": "TGStars_Official",
                "url": "https://tg-stars-free.icu/claim", "status": ThreatStatus.NEW,
                "reasons": ["Premium firibgarlik", "Shubhali TLD (.icu)"],
                "source_app": "Telegram", "device_idx": 0, "days_ago": 6,
            },
            {
                "source": ThreatSource.AUTO_TELEGRAM, "label": ThreatLabel.SUSPICIOUS,
                "message": "Telegram Premium 1 yillik bepul obuna! Ro'yxatdan o'ting: https://premium-tg.cam/free",
                "risk": 82, "confidence": 79, "sender": "PremiumGiftUZ",
                "url": "https://premium-tg.cam/free", "status": ThreatStatus.FALSE_POSITIVE,
                "reasons": ["Premium firibgarlik ehtimoli"],
                "source_app": "Telegram", "device_idx": 1, "days_ago": 8,
            },
            {
                "source": ThreatSource.AUTO_TELEGRAM, "label": ThreatLabel.DANGEROUS,
                "message": "\U0001f381 Sizga Telegram Stars sovg'a qilindi! Qabul qiling: https://stars-gift.buzz/get",
                "risk": 85, "confidence": 82, "sender": "StarsGiveaway",
                "url": "https://stars-gift.buzz/get", "status": ThreatStatus.NEW,
                "reasons": ["Sovg'a firibgarligi", "Shubhali TLD (.buzz)"],
                "source_app": "Telegram", "device_idx": 2, "days_ago": 2,
            },

            # ��─ 4 Brand impersonation ───────��───────────────────────
            {
                "source": ThreatSource.AUTO_SMS, "label": ThreatLabel.DANGEROUS,
                "message": "Payme hisobingizga 500 000 so'm tushdi. Tasdiqlang: https://payme-check.ml/verify",
                "risk": 93, "confidence": 90, "sender": "Payme_Info",
                "url": "https://payme-check.ml/verify", "status": ThreatStatus.CONFIRMED,
                "reasons": ["Brend taqlidi (Payme)", "Shubhali TLD (.ml)"],
                "device_idx": 0, "days_ago": 4,
            },
            {
                "source": ThreatSource.AUTO_SMS, "label": ThreatLabel.DANGEROUS,
                "message": "Click ilovasida muammo aniqlandi. Yangilang: https://click-update.ga/app",
                "risk": 90, "confidence": 87, "sender": "+998901234500",
                "url": "https://click-update.ga/app", "status": ThreatStatus.NEW,
                "reasons": ["Brend taqlidi (Click)", "Shubhali TLD (.ga)"],
                "device_idx": 1, "days_ago": 1,
            },
            {
                "source": ThreatSource.AUTO_SMS, "label": ThreatLabel.DANGEROUS,
                "message": "Uzum Market buyurtmangiz bekor qilindi. Qaytarish: https://uzum-refund.tk/claim",
                "risk": 88, "confidence": 85, "sender": "UzumShop",
                "url": "https://uzum-refund.tk/claim", "status": ThreatStatus.ACTIONED,
                "reasons": ["Brend taqlidi (Uzum)", "Shubhali TLD (.tk)"],
                "device_idx": 2, "days_ago": 6,
            },
            {
                "source": ThreatSource.AUTO_SMS, "label": ThreatLabel.DANGEROUS,
                "message": "Kapitalbank: Kartangizdan 2 000 000 so'm yechildi. Bekor qilish: https://kapital-bank.cf/cancel",
                "risk": 95, "confidence": 92, "sender": "+998712220011",
                "url": "https://kapital-bank.cf/cancel", "status": ThreatStatus.NEW,
                "reasons": ["Brend taqlidi", "Shubhali TLD (.cf)", "Shoshilinchlik yaratish"],
                "device_idx": 0, "days_ago": 0,
            },

            # ── 2 Manual submissions ────────────────────────────────
            {
                "source": ThreatSource.MANUAL, "label": ThreatLabel.DANGEROUS,
                "message": "Salom! Men sizning do'stingizman. Menga qarz pul kerak, 100$ yuboring shu kartaga.",
                "risk": 75, "confidence": 70, "sender": "+998951110000",
                "url": None, "status": ThreatStatus.FALSE_POSITIVE,
                "reasons": ["Foydalanuvchi tomonidan bildirilgan"],
                "device_idx": 1, "days_ago": 10,
            },
            {
                "source": ThreatSource.MANUAL, "label": ThreatLabel.SUSPICIOUS,
                "message": "Yutuq! Siz 10 000 000 so'm yutdingiz! Olish uchun: https://prize-uz.xyz/win",
                "risk": 78, "confidence": 74, "sender": "LOTEREYA",
                "url": "https://prize-uz.xyz/win", "status": ThreatStatus.CONFIRMED,
                "reasons": ["Sovg'a firibgarligi ehtimoli"],
                "device_idx": 2, "days_ago": 12,
            },
        ]

        created_threats = []
        for i, td in enumerate(threats_data):
            threat = Threat(
                mobile_id=f"demo-threat-{i+1:03d}",
                source=td["source"],
                message_truncated=td["message"],
                risk_score=td["risk"],
                confidence=td["confidence"],
                label=td["label"],
                reasons=td.get("reasons", []),
                recommendations=["Havolani ochmang", "SMS ni o'chirib tashlang"],
                analyzed_at_device=now - timedelta(days=td["days_ago"], hours=1),
                sender_name=td.get("sender"),
                source_app=td.get("source_app"),
                detected_file_name=td.get("file_name"),
                detected_file_type=td.get("file_type"),
                detected_url=td.get("url"),
                device_id=devices[td["device_idx"]].id,
                status=td["status"],
                received_at=now - timedelta(days=td["days_ago"]),
                updated_at=now - timedelta(days=td["days_ago"]),
            )
            session.add(threat)
            await session.flush()

            # Apply auto-tags
            tags = apply_auto_tags(threat)
            threat.auto_tags = tags

            # Set actioned_by for confirmed/actioned
            if td["status"] in (ThreatStatus.CONFIRMED, ThreatStatus.ACTIONED):
                threat.actioned_by = admin.id
                threat.actioned_at = now - timedelta(days=td["days_ago"]) + timedelta(hours=2)

            created_threats.append(threat)

        await session.flush()

        # Update device counters
        for i, d in enumerate(devices):
            d.total_threats_reported = sum(
                1 for td in threats_data if td["device_idx"] == i
            )

        # ── Pre-seed 2 AI analyses ──────────────────────────────────
        ai1 = AIAnalysis(
            threat_id=created_threats[0].id,
            severity_assessment="critical",
            threat_type="credential_phishing",
            analysis_text=(
                "This is a classic credential phishing attack targeting SQB Bank customers in Uzbekistan. "
                "The attacker sends an SMS claiming the victim's bank card has been blocked, creating urgency "
                "to trick them into clicking a malicious URL (sqb-login.xyz). The .xyz TLD is a strong indicator "
                "of a phishing domain - legitimate SQB Bank uses sqb.uz. The URL contains '/verify' path, "
                "designed to mimic a bank verification page where the attacker harvests card numbers, PINs, "
                "and OTP codes. This attack pattern is widespread in Central Asia and specifically targets "
                "UzCard and Humo card holders."
            ),
            recommended_actions=[
                "Block the domain sqb-login.xyz at the network level",
                "Issue a customer advisory about this specific phishing campaign",
                "Report the domain to the registrar for takedown",
                "Check if any customers accessed this URL in recent logs",
                "Coordinate with UzCard/Humo to monitor for compromised cards",
            ],
            ioc_indicators={
                "urls": ["https://sqb-login.xyz/verify"],
                "domains": ["sqb-login.xyz"],
                "phone_numbers": ["+998901234567"],
                "file_hashes": [],
                "keywords": ["bloklandi", "tiklash", "kartangiz"],
            },
            similar_pattern_description=(
                "Classic Uzbek bank card blocking scam targeting UzCard/Humo users. "
                "This pattern has been observed since 2024 with variations using different "
                "bank names (SQB, Kapitalbank, Asaka) and different TLDs (.xyz, .top, .club)."
            ),
            confidence_score=95,
            model_used="claude-sonnet-4-20250514",
            requested_by=admin.id,
        )
        session.add(ai1)

        ai2 = AIAnalysis(
            threat_id=created_threats[5].id,
            severity_assessment="critical",
            threat_type="malware_distribution",
            analysis_text=(
                "This is a social engineering attack combined with malware distribution via Telegram. "
                "The attacker uses a classic 'curiosity lure' technique ('Bu senmi rasmda?'/'Is this you in the photo?') "
                "to trick the victim into downloading a malicious APK file. The message plays on the victim's "
                "curiosity and social anxiety. The linked .apk file (app.apk) is almost certainly Android malware "
                "that could steal banking credentials, intercept SMS OTP codes, or provide remote access to the device. "
                "The Telegram link (t.me/photosuz) is a distribution channel specifically targeting Uzbek users."
            ),
            recommended_actions=[
                "Report the Telegram channel t.me/photosuz for malware distribution",
                "Extract and analyze the APK file for specific malware indicators",
                "Issue a warning to customers about 'Bu senmi' curiosity lure attacks",
                "Check if the APK communicates with known C2 servers",
                "Coordinate with Telegram Trust & Safety for channel takedown",
            ],
            ioc_indicators={
                "urls": ["https://t.me/photosuz/app.apk"],
                "domains": ["t.me"],
                "phone_numbers": [],
                "file_hashes": [],
                "keywords": ["bu senmi", "rasmda"],
            },
            similar_pattern_description=(
                "Widespread 'Is this you in the photo?' social engineering lure, extremely common in "
                "Uzbekistan and Central Asia. This variant distributes Android APKs through Telegram channels. "
                "The malware typically belongs to the SpyNote or Cerberus family of Android banking trojans."
            ),
            confidence_score=93,
            model_used="claude-sonnet-4-20250514",
            requested_by=admin.id,
        )
        session.add(ai2)

        # ── Brand Assets ─────────────────────────────────────────────
        brand_assets_data = [
            (BrandAssetType.DOMAIN, "sqb.uz"),
            (BrandAssetType.DOMAIN, "online.sqb.uz"),
            (BrandAssetType.APP_NAME, "SQB Mobile"),
            (BrandAssetType.APP_PACKAGE, "uz.sqb.mobile"),
            (BrandAssetType.SOCIAL_HANDLE, "@sqb_bank"),
            (BrandAssetType.KEYWORD, "sqb"),
            (BrandAssetType.KEYWORD, "\u0441\u043a\u0431"),
            (BrandAssetType.KEYWORD, "sqbank"),
            (BrandAssetType.KEYWORD, "uzcard"),
            (BrandAssetType.KEYWORD, "humo"),
        ]
        for asset_type, value in brand_assets_data:
            ba = BrandAsset(
                asset_type=asset_type,
                value=value,
                is_active=True,
                created_by=admin.id,
            )
            session.add(ba)

        await session.flush()
        print(f"[seed_demo] Seeded {len(brand_assets_data)} brand assets.")

        # ── Scanner Patterns ────────────────────────────────────────
        patterns_data = [
            # Wide catch-all: any domain containing "sqb"
            ("domain", r".*sqb.*\..*", "SQB nomi bor har qanday domen"),
            # Typosquat substitutions
            ("typosquat", r"s[q9g]b", "SQB typosquat — q/9/g almashtirish"),
            # Brand + action word combos
            ("keyword", r"sqb[-_.]?(bank|mobile|login|secure|verify|card|online|pay)", "SQB brend + amal so'zlari"),
            # Cyrillic homoglyphs
            ("homoglyph", r"[\u0441c][\u043ak][\u0431b]", "SQB kirill gomoglif pattern"),
            # Uzbek bank brand monitoring
            ("keyword", r"(uzcard|humo|payme|click)[-_.]?(verify|secure|login|update|check)", "O'zbek bank brendlari + fishing so'zlari"),
            # Catch suspicious TLD combos with bank keywords
            ("domain", r"(bank|card|pay|login|secure)\.(xyz|top|club|icu|buzz|cam|ml|ga|cf|tk)", "Bank kalit so'zlari + shubhali TLD"),
            # Any domain with "uz" + banking terms on suspicious TLDs
            ("domain", r"uz.*(bank|card|pay)\.(xyz|top|club|icu|cam|tk)", "UZ + bank so'zi shubhali TLD da"),
        ]
        for ptype, regex, desc in patterns_data:
            sp = ScannerPattern(
                pattern_type=ptype,
                regex_pattern=regex,
                description=desc,
                is_active=True,
                created_by=admin.id,
                matches_found=0,
            )
            session.add(sp)

        await session.flush()
        print(f"[seed_demo] Seeded {len(patterns_data)} scanner patterns.")

        # ── Scan Run History ────────────────────────────────────────
        scan_runs_data = [
            (ScannerType.DOMAIN, ScanRunStatus.COMPLETED, 8, 2, 245, None, None),
            (ScannerType.DOMAIN, ScanRunStatus.COMPLETED, 6, 1, 245, None, None),
            (ScannerType.PHISHING, ScanRunStatus.COMPLETED, 4, 3, 187, None, None),
            (ScannerType.PHISHING, ScanRunStatus.FAILED, 2, 0, 0, ["crt.sh timeout"], None),
            (ScannerType.APP_STORE, ScanRunStatus.COMPLETED, 12, 2, 30, None, None),
            (ScannerType.APP_STORE, ScanRunStatus.COMPLETED, 10, 1, 28, None, None),
            (ScannerType.SOCIAL, ScanRunStatus.COMPLETED, 3, 4, 15, None, None),
            (ScannerType.SOCIAL, ScanRunStatus.COMPLETED, 5, 2, 12, None, None),
            (ScannerType.PASTE, ScanRunStatus.COMPLETED, 7, 1, 42, None, None),
            (ScannerType.PASTE, ScanRunStatus.COMPLETED, 9, 0, 38, None, None),
        ]
        for i, (stype, status, hours_ago, threats, items, errors, details) in enumerate(scan_runs_data):
            started = now - timedelta(hours=hours_ago)
            duration = 12.5 + i * 3.7
            sr = ScanRun(
                scanner_type=stype,
                status=status,
                started_at=started,
                completed_at=started + timedelta(seconds=duration),
                duration_seconds=duration,
                threats_found=threats,
                items_scanned=items,
                errors=errors,
                details=details,
            )
            session.add(sr)

        await session.flush()
        print(f"[seed_demo] Seeded {len(scan_runs_data)} scan run records.")

        # ── Scanner-discovered threats ──────────────────────────────
        scanner_threats_data = [
            {
                "source": ThreatSource.SCANNER_DOMAIN, "label": ThreatLabel.DANGEROUS,
                "message": "Typosquat domen aniqlandi: sqb-login.xyz. Bu domen SQB brendiga o'xshash va fishing hujumi uchun ishlatilishi mumkin.",
                "risk": 92, "confidence": 80,
                "url": "https://sqb-login.xyz", "status": ThreatStatus.NEW,
                "reasons": ["Domen 'sqb-login.xyz' brend domeniga o'xshash", "DNS resolve muvaffaqiyatli", "Shubhali TLD (.xyz)"],
                "days_ago": 1,
            },
            {
                "source": ThreatSource.SCANNER_DOMAIN, "label": ThreatLabel.SUSPICIOUS,
                "message": "Typosquat domen aniqlandi: sqb-mobile.top. Bu domen SQB Mobile ilovasini taqlid qilishi mumkin.",
                "risk": 85, "confidence": 78,
                "url": "https://sqb-mobile.top", "status": ThreatStatus.NEW,
                "reasons": ["Domen 'sqb-mobile.top' brend domeniga o'xshash", "Shubhali TLD (.top)"],
                "days_ago": 2,
            },
            {
                "source": ThreatSource.SCANNER_PHISHING, "label": ThreatLabel.DANGEROUS,
                "message": "Fishing sertifikati aniqlandi: secure-sqb.icu. CT logda SQB brendiga o'xshash domen uchun SSL sertifikat chiqarilgan.",
                "risk": 90, "confidence": 82,
                "url": "https://secure-sqb.icu", "status": ThreatStatus.CONFIRMED,
                "reasons": ["CT logda brend bilan bog'liq sertifikat topildi", "Shubhali TLD (.icu)"],
                "days_ago": 0,
            },
            {
                "source": ThreatSource.SCANNER_PHISHING, "label": ThreatLabel.DANGEROUS,
                "message": "URLhaus'da zararli URL topildi: https://sqb-verify.club/login. Bu URL SQB brendiga bog'liq bo'lishi mumkin.",
                "risk": 93, "confidence": 85,
                "url": "https://sqb-verify.club/login", "status": ThreatStatus.NEW,
                "reasons": ["URLhaus zararli URL bazasida topildi", "Xavf turi: phishing"],
                "days_ago": 1,
            },
            {
                "source": ThreatSource.SCANNER_APP_STORE, "label": ThreatLabel.SUSPICIOUS,
                "message": "Google Play'da shubhali ilova: 'SQB Mobile Banking - Unofficial' (com.fake.sqb.banking). Bu ilova SQB brendini taqlid qilishi mumkin.",
                "risk": 80, "confidence": 70,
                "url": "https://play.google.com/store/apps/details?id=com.fake.sqb.banking", "status": ThreatStatus.NEW,
                "reasons": ["Google Play'da brend nomiga o'xshash ilova", "Past reyting"],
                "days_ago": 3,
            },
            {
                "source": ThreatSource.SCANNER_DOMAIN, "label": ThreatLabel.DANGEROUS,
                "message": "Typosquat domen aniqlandi: s9b-bank.xyz. Homoglyph almashtirish (q→9) va shubhali TLD.",
                "risk": 88, "confidence": 82,
                "url": "https://s9b-bank.xyz", "status": ThreatStatus.NEW,
                "reasons": ["Homoglyph almashtirish: q→9", "Shubhali TLD (.xyz)", "DNS resolve muvaffaqiyatli"],
                "days_ago": 0,
            },
            {
                "source": ThreatSource.SCANNER_DOMAIN, "label": ThreatLabel.DANGEROUS,
                "message": "Typosquat domen aniqlandi: sqb-online.cam. SQB Online Banking taqlidi.",
                "risk": 90, "confidence": 85,
                "url": "https://sqb-online.cam", "status": ThreatStatus.NEW,
                "reasons": ["'sqb-online' brend domeniga o'xshash", "Shubhali TLD (.cam)", "DNS resolve muvaffaqiyatli"],
                "days_ago": 0,
            },
            {
                "source": ThreatSource.SCANNER_PASTE, "label": ThreatLabel.DANGEROUS,
                "message": "GitHub'da SQB bilan bog'liq ma'lumotlar sizib chiqishi: sqb.uz API kaliti va mijozlar bazasi aniqlandi.",
                "risk": 85, "confidence": 75,
                "url": "https://github.com/leaker123/configs/blob/main/sqb_dump.txt", "status": ThreatStatus.NEW,
                "reasons": ["GitHub'da shubhali kontent: 'sqb.uz password'", "API kalitlari sizib chiqishi ehtimoli"],
                "days_ago": 1,
            },
        ]

        for i, td in enumerate(scanner_threats_data):
            threat = Threat(
                mobile_id=f"scanner-demo-{i+1:03d}",
                source=td["source"],
                message_truncated=td["message"],
                risk_score=td["risk"],
                confidence=td["confidence"],
                label=td["label"],
                reasons=td.get("reasons", []),
                recommendations=["Domen/URL ni bloklang", "Xavfsizlik jamoasiga xabar bering"],
                detected_url=td.get("url"),
                device_id=None,
                status=td["status"],
                received_at=now - timedelta(days=td["days_ago"]),
                updated_at=now - timedelta(days=td["days_ago"]),
            )
            session.add(threat)
            await session.flush()
            tags = apply_auto_tags(threat)
            threat.auto_tags = tags

            if td["status"] == ThreatStatus.CONFIRMED:
                threat.actioned_by = admin.id
                threat.actioned_at = now - timedelta(days=td["days_ago"]) + timedelta(hours=1)

        await session.flush()
        print(f"[seed_demo] Seeded {len(scanner_threats_data)} scanner-discovered threats.")

        await session.commit()
        print(f"[seed_demo] Seeded {len(threats_data)} threats, 3 devices, 2 AI analyses.")
        print("[seed_demo] Admin: admin@sqb.uz / SafeTalk2026!")
        print("[seed_demo] Analyst: analyst@sqb.uz / Analyst2026!")

    await engine.dispose()


if __name__ == "__main__":
    asyncio.run(seed())
