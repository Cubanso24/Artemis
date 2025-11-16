"""
Logging configuration for the Artemis threat hunting system.
"""

import logging
import sys
from typing import Optional
from datetime import datetime


class ArtemisLogger:
    """
    Custom logger for Artemis threat hunting system.

    Provides structured logging with context for security operations.
    """

    @staticmethod
    def setup_logger(
        name: str,
        level: int = logging.INFO,
        log_file: Optional[str] = None
    ) -> logging.Logger:
        """
        Set up a logger with appropriate handlers and formatting.

        Args:
            name: Logger name (typically module name)
            level: Logging level
            log_file: Optional file to write logs to

        Returns:
            Configured logger
        """
        logger = logging.getLogger(name)
        logger.setLevel(level)

        # Avoid duplicate handlers
        if logger.handlers:
            return logger

        # Create formatter
        formatter = logging.Formatter(
            fmt='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )

        # Console handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(level)
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)

        # File handler (optional)
        if log_file:
            file_handler = logging.FileHandler(log_file)
            file_handler.setLevel(level)
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)

        return logger

    @staticmethod
    def get_logger(name: str) -> logging.Logger:
        """Get or create a logger."""
        return logging.getLogger(name)


def log_agent_activity(
    logger: logging.Logger,
    agent_name: str,
    action: str,
    details: dict
):
    """
    Log agent activity in a structured format.

    Args:
        logger: Logger instance
        agent_name: Name of the agent
        action: Action being performed
        details: Additional details
    """
    logger.info(
        f"Agent: {agent_name} | Action: {action} | Details: {details}"
    )


def log_detection(
    logger: logging.Logger,
    agent_name: str,
    severity: str,
    confidence: float,
    description: str
):
    """
    Log a threat detection.

    Args:
        logger: Logger instance
        agent_name: Name of the detecting agent
        severity: Severity level
        confidence: Confidence score
        description: Detection description
    """
    logger.warning(
        f"DETECTION | Agent: {agent_name} | Severity: {severity} | "
        f"Confidence: {confidence:.2f} | {description}"
    )


def log_meta_learner_decision(
    logger: logging.Logger,
    decision_type: str,
    details: dict
):
    """
    Log meta-learner decisions.

    Args:
        logger: Logger instance
        decision_type: Type of decision
        details: Decision details
    """
    logger.info(
        f"META-LEARNER | Decision: {decision_type} | Details: {details}"
    )
