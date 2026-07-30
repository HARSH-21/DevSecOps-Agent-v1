"""
config.py

Central configuration manager for AI DevSecOps Agent.

Responsibilities:
- Load environment variables
- Manage project paths
- Detect security tools
- Configure LLM
- Provide global settings
"""

from pathlib import Path
from dotenv import load_dotenv
import os
import shutil


# =====================================================
# Environment
# =====================================================

load_dotenv()


# =====================================================
# Agent Information
# =====================================================

AGENT_NAME = "AI DevSecOps Agent"
AGENT_VERSION = "0.1.0"


BASE_DIR = Path(__file__).resolve().parent

# =====================================================
# AI Configuration
# =====================================================

AI_PROVIDER = "ollama"

AI_MODEL = "qwen2.5:3b"

OLLAMA_HOST = "http://localhost:11434"

AI_TIMEOUT = 180

AI_TEMPERATURE = 0.2

AI_MAX_RETRIES = 2


# =====================================================
# Project Directories
# =====================================================

OUTPUT_DIR = BASE_DIR / os.getenv(
    "OUTPUT_DIR",
    "outputs"
)

REPORT_DIR = BASE_DIR / os.getenv(
    "REPORT_DIR",
    "reports"
)

LOG_DIR = BASE_DIR / os.getenv(
    "LOG_DIR",
    "logs"
)


for directory in [
    OUTPUT_DIR,
    REPORT_DIR,
    LOG_DIR
]:

    directory.mkdir(
        parents=True,
        exist_ok=True
    )



# =====================================================
# LLM Configuration
# =====================================================

OLLAMA_HOST = os.getenv(
    "OLLAMA_HOST",
    "http://localhost:11434"
)


OLLAMA_MODEL = os.getenv(
    "OLLAMA_MODEL",
    "qwen2.5:7b"
)



# =====================================================
# Tool Discovery
# =====================================================

def find_tool(
    env_variable: str,
    executable: str
):

    """
    Detect security tool.

    Priority:
    1. Environment variable path
    2. System PATH
    """

    custom_path = os.getenv(
        env_variable
    )


    if custom_path:

        return custom_path


    return shutil.which(
        executable
    )



# =====================================================
# Security Capability Registry
# =====================================================

TOOLS = {


    # ---------------------------------
    # Static Application Security Testing
    # ---------------------------------

    "sast": {

        "semgrep":
            find_tool(
                "SEMGREP_PATH",
                "semgrep"
            )

    },


    # ---------------------------------
    # Software Supply Chain Security
    # ---------------------------------

    "dependency_security": {


        "osv":

            find_tool(
                "OSV_PATH",
                "osv-scanner"
            ),



        "syft":

            find_tool(
                "SYFT_PATH",
                "syft"
            ),



        "grype":

            find_tool(
                "GRYPE_PATH",
                "grype"
            )

    },


    # ---------------------------------
    # Secret Detection
    # ---------------------------------

    "secrets": {


        "gitleaks":

            find_tool(
                "GITLEAKS_PATH",
                "gitleaks"
            )

    },


    # ---------------------------------
    # Container and Infrastructure
    # ---------------------------------

    "container_security": {


        "trivy":

            find_tool(
                "TRIVY_PATH",
                "trivy"
            ),


        "checkov":

            find_tool(
                "CHECKOV_PATH",
                "checkov"
            )

    }

}



# =====================================================
# Feature Flags
# =====================================================

ENABLE_SAST = os.getenv(
    "ENABLE_SAST",
    "true"
).lower() == "true"


ENABLE_DEPENDENCY_SECURITY = os.getenv(
    "ENABLE_DEPENDENCY_SECURITY",
    "true"
).lower() == "true"


ENABLE_SECRETS = os.getenv(
    "ENABLE_SECRETS",
    "true"
).lower() == "true"


ENABLE_CONTAINER_SECURITY = os.getenv(
    "ENABLE_CONTAINER_SECURITY",
    "true"
).lower() == "true"



# =====================================================
# Logging
# =====================================================

LOG_LEVEL = os.getenv(
    "LOG_LEVEL",
    "INFO"
)



# =====================================================
# Reporting
# =====================================================

DEFAULT_REPORT_FORMAT = os.getenv(
    "REPORT_FORMAT",
    "json"
)



# =====================================================
# GitHub
# =====================================================

GITHUB_TOKEN = os.getenv(
    "GITHUB_TOKEN",
    ""
)



# =====================================================
# Validation
# =====================================================

def validate_configuration():


    print("=" * 70)

    print(
        AGENT_NAME
    )

    print("=" * 70)


    print(
        f"Version : {AGENT_VERSION}"
    )


    print(
        f"LLM     : {OLLAMA_MODEL}"
    )


    print("\nSecurity Capabilities")
    print("-" * 70)



    for capability, tools in TOOLS.items():


        print(
            f"\n[{capability.upper()}]"
        )


        for tool, path in tools.items():


            if path:

                print(
                    f"  [✓] {tool:<12} {path}"
                )

            else:

                print(
                    f"  [ ] {tool:<12} Not Installed"
                )



    print("-" * 70)


    return True



if __name__ == "__main__":

    validate_configuration()