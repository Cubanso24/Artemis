"""
Multi-armed bandit algorithms for agent selection optimization.
"""

import numpy as np
from typing import Dict, List, Tuple
from dataclasses import dataclass, field


@dataclass
class ArmStatistics:
    """Statistics for a single bandit arm (agent activation strategy)."""
    successes: int = 0
    failures: int = 0
    total_pulls: int = 0
    total_reward: float = 0.0

    @property
    def success_rate(self) -> float:
        """Calculate success rate."""
        if self.total_pulls == 0:
            return 0.5  # Optimistic initial value
        return self.successes / self.total_pulls

    @property
    def average_reward(self) -> float:
        """Calculate average reward."""
        if self.total_pulls == 0:
            return 0.0
        return self.total_reward / self.total_pulls


class ThompsonSampling:
    """
    Thompson Sampling for contextual multi-armed bandit problems.

    Used by the meta-learner to optimize agent activation strategies
    through exploration-exploitation trade-off.

    Each "arm" represents an agent activation strategy, and the bandit
    learns which strategies work best in different network contexts.
    """

    def __init__(self, n_arms: int, alpha_prior: float = 1.0, beta_prior: float = 1.0):
        """
        Initialize Thompson Sampling.

        Args:
            n_arms: Number of arms (agent activation strategies)
            alpha_prior: Prior alpha parameter for Beta distribution
            beta_prior: Prior beta parameter for Beta distribution
        """
        self.n_arms = n_arms
        self.alpha_prior = alpha_prior
        self.beta_prior = beta_prior

        # Statistics for each arm
        self.arms: Dict[int, ArmStatistics] = {
            i: ArmStatistics() for i in range(n_arms)
        }

        # Beta distribution parameters (successes, failures)
        self.alpha = np.ones(n_arms) * alpha_prior
        self.beta = np.ones(n_arms) * beta_prior

    def select_arm(self, context: np.ndarray = None) -> int:
        """
        Select an arm using Thompson Sampling.

        Args:
            context: Optional context vector (not used in basic version)

        Returns:
            Selected arm index
        """
        # Sample from Beta distribution for each arm
        samples = np.random.beta(self.alpha, self.beta)

        # Select arm with highest sample
        return int(np.argmax(samples))

    def update(self, arm: int, reward: float):
        """
        Update arm statistics after observing reward.

        Args:
            arm: Arm that was pulled
            reward: Observed reward (0.0 to 1.0)
        """
        stats = self.arms[arm]
        stats.total_pulls += 1
        stats.total_reward += reward

        # Binary outcome: success if reward > threshold
        if reward > 0.5:
            stats.successes += 1
            self.alpha[arm] += 1
        else:
            stats.failures += 1
            self.beta[arm] += 1

    def get_arm_statistics(self, arm: int) -> ArmStatistics:
        """Get statistics for a specific arm."""
        return self.arms[arm]

    def get_best_arm(self) -> int:
        """Get arm with highest expected value (exploitation only)."""
        expected_values = self.alpha / (self.alpha + self.beta)
        return int(np.argmax(expected_values))

    def get_arm_probabilities(self) -> np.ndarray:
        """Get current probability of selecting each arm."""
        # Monte Carlo estimate
        n_samples = 10000
        samples = np.random.beta(
            self.alpha[:, np.newaxis],
            self.beta[:, np.newaxis],
            size=(self.n_arms, n_samples)
        )
        probabilities = np.mean(np.argmax(samples, axis=0)[:, np.newaxis] == np.arange(self.n_arms), axis=0)
        return probabilities

    def reset_arm(self, arm: int):
        """Reset statistics for a specific arm."""
        self.arms[arm] = ArmStatistics()
        self.alpha[arm] = self.alpha_prior
        self.beta[arm] = self.beta_prior


class ContextualBandit:
    """
    Contextual multi-armed bandit for context-aware agent selection.

    Extends Thompson Sampling to consider network state context when
    selecting agent activation strategies.
    """

    def __init__(self, n_arms: int, context_dim: int):
        """
        Initialize Contextual Bandit.

        Args:
            n_arms: Number of arms (strategies)
            context_dim: Dimensionality of context vectors
        """
        self.n_arms = n_arms
        self.context_dim = context_dim

        # Linear models for each arm: reward = context @ weights + noise
        self.weights = np.zeros((n_arms, context_dim))
        self.covariance = [np.eye(context_dim) for _ in range(n_arms)]

        # Regularization
        self.lambda_reg = 1.0

        # Statistics
        self.arms: Dict[int, ArmStatistics] = {
            i: ArmStatistics() for i in range(n_arms)
        }

    def select_arm(self, context: np.ndarray) -> int:
        """
        Select arm based on context using Thompson Sampling.

        Args:
            context: Context vector (network state)

        Returns:
            Selected arm index
        """
        # Sample weights from posterior
        sampled_rewards = []

        for arm in range(self.n_arms):
            # Sample from multivariate normal
            sampled_weights = np.random.multivariate_normal(
                self.weights[arm],
                self.covariance[arm]
            )
            # Predict reward
            reward = np.dot(context, sampled_weights)
            sampled_rewards.append(reward)

        return int(np.argmax(sampled_rewards))

    def update(self, arm: int, context: np.ndarray, reward: float):
        """
        Update arm model after observing reward.

        Args:
            arm: Selected arm
            context: Context vector used
            reward: Observed reward
        """
        # Update statistics
        stats = self.arms[arm]
        stats.total_pulls += 1
        stats.total_reward += reward

        if reward > 0.5:
            stats.successes += 1
        else:
            stats.failures += 1

        # Update linear model (Bayesian linear regression)
        # Update covariance
        context_outer = np.outer(context, context)
        self.covariance[arm] = np.linalg.inv(
            np.linalg.inv(self.covariance[arm]) + context_outer
        )

        # Update weights
        weight_update = self.covariance[arm] @ context * reward
        self.weights[arm] += weight_update

    def get_best_arm(self, context: np.ndarray) -> int:
        """Get arm with highest expected reward for given context."""
        expected_rewards = [
            np.dot(context, self.weights[arm])
            for arm in range(self.n_arms)
        ]
        return int(np.argmax(expected_rewards))

    def get_arm_statistics(self, arm: int) -> ArmStatistics:
        """Get statistics for a specific arm."""
        return self.arms[arm]
