"""SMTP email delivery for user onboarding."""

import smtplib
from datetime import datetime, timezone
from email.message import EmailMessage
from html import escape
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from app.core.config import Settings, get_settings


class EmailDeliveryError(Exception):
    """Raised when an email cannot be accepted by the SMTP server."""


class EmailService:
    """Small SMTP adapter for transactional onboarding emails."""

    def __init__(self, settings: Settings) -> None:
        self._smtp_host = settings.smtp_host
        self._smtp_port = settings.smtp_port
        self._from_email = str(settings.smtp_from_email)
        self._from_name = settings.smtp_from_name
        self._timeout_seconds = settings.smtp_timeout_seconds
        self._verification_url = settings.email_verification_url

    def send_verification_email(
        self,
        *,
        recipient_email: str,
        recipient_name: str,
        raw_token: str,
        expires_at: datetime,
    ) -> None:
        """Send a verification link without logging or persisting its raw token."""
        verification_url = self._build_verification_url(raw_token)
        expiration = expires_at.astimezone(timezone.utc).strftime(
            "%Y-%m-%d at %H:%M UTC"
        )

        message = EmailMessage()
        message["Subject"] = "Verify your Almafrica email address"
        message["From"] = f"{self._from_name} <{self._from_email}>"
        message["To"] = recipient_email
        message.set_content(
            f"Hello {recipient_name},\n\n"
            "Thank you for creating your Almafrica account. Verify your email "
            "address using the link below:\n\n"
            f"{verification_url}\n\n"
            f"This link expires on {expiration}. If you did not create this "
            "account, you can ignore this email.\n\n"
            "The Almafrica team\n"
        )
        message.add_alternative(
            "<!doctype html>"
            "<html><body>"
            f"<p>Hello {escape(recipient_name)},</p>"
            "<p>Thank you for creating your Almafrica account. Verify your "
            "email address using the link below:</p>"
            f'<p><a href="{escape(verification_url, quote=True)}">'
            "Verify my email address</a></p>"
            f"<p>This link expires on {escape(expiration)}.</p>"
            "<p>If you did not create this account, you can ignore this email.</p>"
            "<p>The Almafrica team</p>"
            "</body></html>",
            subtype="html",
        )

        try:
            with smtplib.SMTP(
                self._smtp_host,
                self._smtp_port,
                timeout=self._timeout_seconds,
            ) as smtp:
                smtp.send_message(message)
        except (OSError, smtplib.SMTPException) as exc:
            raise EmailDeliveryError("SMTP delivery failed") from exc

    def _build_verification_url(self, raw_token: str) -> str:
        """Add the secret token as one encoded query parameter."""
        parts = urlsplit(self._verification_url)
        query = parse_qsl(parts.query, keep_blank_values=True)
        query.append(("token", raw_token))
        return urlunsplit(
            (parts.scheme, parts.netloc, parts.path, urlencode(query), parts.fragment)
        )


def get_email_service() -> EmailService:
    """Build the email delivery dependency from application settings."""
    return EmailService(get_settings())
