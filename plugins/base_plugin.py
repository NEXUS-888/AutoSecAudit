from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
import logging
import shutil
import config

logger = logging.getLogger(__name__)


class BaseScanner(ABC):
    """Abstract base class for all security scanning plugins."""

    def __init__(self, mock_mode: Optional[bool] = None):
        self.target: str = ""
        self.mock_mode = mock_mode if mock_mode is not None else config.MOCK_MODE
        self._tool_available: Optional[bool] = None
        self.discovered_endpoints: list = []  # populated by engine from crawler

    def set_discovered_endpoints(self, endpoints: list) -> None:
        """Set discovered endpoints from the web crawler."""
        self.discovered_endpoints = endpoints

    @abstractmethod
    def configure(self, target: str) -> None:
        """Configure the scanner with target URL/IP."""
        self.target = target

    @abstractmethod
    def run(self) -> None:
        """Execute the scanning tool."""
        pass

    @abstractmethod
    def parse_output(self) -> Dict[str, Any]:
        """Parse tool output and return standardized findings."""
        pass

    def check_tool_available(self, tool_name: str) -> bool:
        """Check if the scanning tool is installed and available."""
        if self._tool_available is not None:
            return self._tool_available

        self._tool_available = shutil.which(tool_name) is not None
        if not self._tool_available:
            logger.warning(f"Tool '{tool_name}' not found. Plugin will run in mock mode.")
        return self._tool_available

    def get_standardized_output(self) -> Dict[str, Any]:
        """Execute run() and parse_output() to get standardized findings."""
        tool_name = self._get_tool_name()
        tool_available = self.check_tool_available(tool_name)
        logger.info(f"[DEBUG] {self.__class__.__name__}: mock_mode={self.mock_mode}, tool={tool_name}, available={tool_available}")
        
        if self.mock_mode:
            logger.info(f"Running {self.__class__.__name__} in MOCK mode")
            return self._get_mock_output()

        if not tool_available:
            logger.warning(f"Skipping {self.__class__.__name__}: tool '{tool_name}' not installed and mock mode is OFF")
            return {"tool_name": tool_name, "findings": []}

        self.run()
        return self.parse_output()

    @abstractmethod
    def _get_tool_name(self) -> str:
        """Return the name of the underlying tool."""
        pass

    @abstractmethod
    def _get_mock_output(self) -> Dict[str, Any]:
        """Return mock findings for development/demo."""
        pass
