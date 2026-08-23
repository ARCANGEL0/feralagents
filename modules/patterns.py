import re


SECRET_PATTERNS = [

    # ─────────────────────────────────────────────
    # AWS
    # ─────────────────────────────────────────────

    (
        "AWS Access Key",
        re.compile(
            r"\bAKIA[0-9A-Z]{16}\b"
        ),
    ),

    (
        "AWS Temporary Access Key",
        re.compile(
            r"\bASIA[0-9A-Z]{16}\b"
        ),
    ),

    (
        "AWS Secret Access Key",
        re.compile(
            r"(?i)\b(?:aws_secret_access_key|aws_secret_key)\b"
            r"\s*[:=]\s*['\"]([^'\"]{20,})['\"]"
        ),
    ),


    # ─────────────────────────────────────────────
    # NVIDIA
    # ─────────────────────────────────────────────

    (
        "NVIDIA API Key",
        re.compile(
            r"\bnvapi-[A-Za-z0-9_-]{20,}\b"
        ),
    ),


    # ─────────────────────────────────────────────
    # GitHub
    # ─────────────────────────────────────────────

    (
        "GitHub Personal Access Token",
        re.compile(
            r"\bghp_[A-Za-z0-9]{36}\b"
        ),
    ),

    (
        "GitHub OAuth Token",
        re.compile(
            r"\bgho_[A-Za-z0-9]{36}\b"
        ),
    ),

    (
        "GitHub User-to-Server Token",
        re.compile(
            r"\bghu_[A-Za-z0-9]{36}\b"
        ),
    ),

    (
        "GitHub Server-to-Server Token",
        re.compile(
            r"\bghs_[A-Za-z0-9]{36}\b"
        ),
    ),

    (
        "GitHub Fine-Grained Token",
        re.compile(
            r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"
        ),
    ),


    # ─────────────────────────────────────────────
    # GitLab
    # ─────────────────────────────────────────────

    (
        "GitLab Personal Access Token",
        re.compile(
            r"\bglpat-[A-Za-z0-9_-]{20,}\b"
        ),
    ),


    # ─────────────────────────────────────────────
    # Slack
    # ─────────────────────────────────────────────

    (
        "Slack Token",
        re.compile(
            r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"
        ),
    ),


    # ─────────────────────────────────────────────
    # Stripe
    # ─────────────────────────────────────────────

    (
        "Stripe Secret Key",
        re.compile(
            r"\bsk_(?:live|test)_[A-Za-z0-9]{16,}\b"
        ),
    ),

    (
        "Stripe Restricted Key",
        re.compile(
            r"\brk_(?:live|test)_[A-Za-z0-9]{16,}\b"
        ),
    ),


    # ─────────────────────────────────────────────
    # OpenAI
    # ─────────────────────────────────────────────

    (
        "OpenAI API Key",
        re.compile(
            r"\bsk-[A-Za-z0-9_-]{20,}\b"
        ),
    ),

    (
        "OpenAI Project API Key",
        re.compile(
            r"\bsk-proj-[A-Za-z0-9_-]{20,}\b"
        ),
    ),


    # ─────────────────────────────────────────────
    # Anthropic
    # ─────────────────────────────────────────────

    (
        "Anthropic API Key",
        re.compile(
            r"\bsk-ant-[A-Za-z0-9_-]{20,}\b"
        ),
    ),


    # ─────────────────────────────────────────────
    # Google / GCP
    # ─────────────────────────────────────────────

    (
        "Google API Key",
        re.compile(
            r"\bAIza[0-9A-Za-z_-]{35}\b"
        ),
    ),

    (
        "Google OAuth Client Secret",
        re.compile(
            r"\bGOCSPX-[A-Za-z0-9_-]{20,}\b"
        ),
    ),


    # ─────────────────────────────────────────────
    # Discord
    # ─────────────────────────────────────────────

    (
        "Discord Bot Token",
        re.compile(
            r"\b[A-Za-z0-9_-]{24,28}\."
            r"[A-Za-z0-9_-]{6}\."
            r"[A-Za-z0-9_-]{25,}\b"
        ),
    ),

    (
        "Discord Webhook",
        re.compile(
            r"https://discord(?:app)?\.com/api/webhooks/"
            r"\d{15,25}/[A-Za-z0-9_-]{20,}"
        ),
    ),


    # ─────────────────────────────────────────────
    # Telegram
    # ─────────────────────────────────────────────

    (
        "Telegram Bot Token",
        re.compile(
            r"\b\d{8,12}:[A-Za-z0-9_-]{35}\b"
        ),
    ),


    # ─────────────────────────────────────────────
    # PyPI
    # ─────────────────────────────────────────────

    (
        "PyPI API Token",
        re.compile(
            r"\bpypi-[A-Za-z0-9_-]{20,}\b"
        ),
    ),


    # ─────────────────────────────────────────────
    # npm
    # ─────────────────────────────────────────────

    (
        "npm Access Token",
        re.compile(
            r"\bnpm_[A-Za-z0-9]{30,}\b"
        ),
    ),


    # ─────────────────────────────────────────────
    # SendGrid
    # ─────────────────────────────────────────────

    (
        "SendGrid API Key",
        re.compile(
            r"\bSG\.[A-Za-z0-9_-]{20,}\."
            r"[A-Za-z0-9_-]{20,}\b"
        ),
    ),


    # ─────────────────────────────────────────────
    # Twilio
    # ─────────────────────────────────────────────

    (
        "Twilio API Key",
        re.compile(
            r"\bSK[0-9a-fA-F]{32}\b"
        ),
    ),


    # ─────────────────────────────────────────────
    # Heroku
    # ─────────────────────────────────────────────

    (
        "Heroku API Key",
        re.compile(
            r"(?i)\bheroku[_-]?(?:api[_-]?)?key\b"
            r"\s*[:=]\s*['\"]([0-9a-f-]{20,})['\"]"
        ),
    ),


    # ─────────────────────────────────────────────
    # HashiCorp / Terraform
    # ─────────────────────────────────────────────

    (
        "HashiCorp Vault Token",
        re.compile(
            r"\bhvs\.[A-Za-z0-9_-]{20,}\b"
        ),
    ),

    (
        "Terraform Cloud Token",
        re.compile(
            r"\b[a-zA-Z0-9]{14,}\.atlasv1\."
            r"[A-Za-z0-9_-]{20,}\b"
        ),
    ),


    # ─────────────────────────────────────────────
    # SSH / Private Keys
    # ─────────────────────────────────────────────

    (
        "RSA Private Key",
        re.compile(
            r"-----BEGIN RSA PRIVATE KEY-----"
        ),
    ),

    (
        "EC Private Key",
        re.compile(
            r"-----BEGIN EC PRIVATE KEY-----"
        ),
    ),

    (
        "DSA Private Key",
        re.compile(
            r"-----BEGIN DSA PRIVATE KEY-----"
        ),
    ),

    (
        "OpenSSH Private Key",
        re.compile(
            r"-----BEGIN OPENSSH PRIVATE KEY-----"
        ),
    ),

    (
        "Generic Private Key",
        re.compile(
            r"-----BEGIN PRIVATE KEY-----"
        ),
    ),

    (
        "Encrypted Private Key",
        re.compile(
            r"-----BEGIN ENCRYPTED PRIVATE KEY-----"
        ),
    ),


    # ─────────────────────────────────────────────
    # JWT
    # ─────────────────────────────────────────────

    (
        "JWT Token",
        re.compile(
            r"\beyJ[A-Za-z0-9_-]{10,}\."
            r"[A-Za-z0-9_-]{10,}\."
            r"[A-Za-z0-9_-]{10,}\b"
        ),
    ),


    # ─────────────────────────────────────────────
    # Basic Auth / Bearer credentials
    # ─────────────────────────────────────────────

    (
        "Bearer Token",
        re.compile(
            r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{20,}"
        ),
    ),

    (
        "Basic Authentication",
        re.compile(
            r"(?i)\bBasic\s+[A-Za-z0-9+/=]{20,}"
        ),
    ),
]
