"""
base_tool.py

Base interface for security tool adapters.
"""


from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any



class BaseTool(ABC):


    def __init__(
        self,
        name: str,
        executable: str
    ):

        self.name = name
        self.executable = executable



    @abstractmethod
    def is_available(self):
        pass



    @abstractmethod
    def build_command(
        self,
        target: Path
    ) -> list[str]:

        pass



    @abstractmethod
    def parse(
        self,
        output: str
    ) -> list[dict[str,Any]]:

        pass



    def normalize(
        self,
        findings
    ):

        normalized = []

        for finding in findings:

            normalized.append({

                "tool":
                    self.name,

                "severity":
                    finding.get(
                        "severity",
                        "UNKNOWN"
                    ),

                "title":
                    finding.get(
                        "title",
                        "Security Finding"
                    ),

                "location":
                    finding.get(
                        "location",
                        ""
                    ),

                "description":
                    finding.get(
                        "description",
                        ""
                    )

            })

        return normalized



    def __str__(self):

        return (
            f"{self.name} ({self.executable})"
        )