"""
executor.py

Central execution engine for security tools.
"""


from __future__ import annotations

import subprocess
import time
from pathlib import Path
from typing import Optional



class ToolExecutor:


    @staticmethod
    def run(
        command:list[str],
        cwd:Optional[Path]=None,
        timeout:int=300
    ):


        start=time.perf_counter()


        try:

            result=subprocess.run(

                            command,

                            cwd=cwd,

                            capture_output=True,

                            text=True,

                            encoding="utf-8",

                            errors="replace",

                            timeout=timeout,

                            shell=False

)


            return {

                "success":
                    result.returncode == 0,

                "exit_code":
                    result.returncode,

                "stdout":
                    result.stdout,

                "stderr":
                    result.stderr,

                "execution_time":
                    round(
                        time.perf_counter()-start,
                        2
                    ),

                "command":
                    command
            }



        except subprocess.TimeoutExpired:


            return {

                "success":False,

                "exit_code":-1,

                "stdout":"",

                "stderr":
                    "Timeout exceeded",

                "command":
                    command

            }



        except Exception as exc:


            return {

                "success":False,

                "exit_code":-2,

                "stdout":"",

                "stderr":
                    str(exc),

                "command":
                    command

            }