//! The retry schedule of `spec/errors.md` §3.1: when to try again, when SMTP
//! becomes allowed, when to give up.

use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};

/// Share of a delay that jitter may add or remove.
const JITTER: f64 = 0.2;

/// Timing parameters. [`Default`] is the specification's schedule; tests and
/// the devnet shorten it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetryPolicy {
    /// Delay before the first retry; doubles with every further attempt.
    pub first_delay: Duration,
    /// Cap for the doubling delay.
    pub max_delay: Duration,
    /// How long an unavailable endpoint is retried before SMTP is used.
    pub fallback_window: Duration,
    /// After this long the message bounces.
    pub give_up: Duration,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            first_delay: Duration::from_mins(1),
            max_delay: Duration::from_hours(1),
            fallback_window: Duration::from_hours(2),
            give_up: Duration::from_hours(5 * 24),
        }
    }
}

/// What a temporary failure says about SMTP fallback (`spec/errors.md` §3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SmtpFallback {
    /// Connection failure, TLS failure, or request-level 5xx: SMTP is allowed
    /// once the fallback window has passed.
    AfterWindow,
    /// The receiver answered and asked for a later retry (e.g.
    /// `rate_limited`, a deferred recipient): SMTP must not bypass it.
    Never,
}

/// The attempts made so far, including the one that just failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct History {
    /// Time of the first attempt; every limit counts from here.
    pub first_attempt: SystemTime,
    /// Number of attempts made, at least 1.
    pub attempts: u32,
    /// Whether every attempt so far, including the last, was
    /// [`SmtpFallback::AfterWindow`].
    pub fallback: SmtpFallback,
}

/// What to do after a temporary failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub enum Step {
    /// Try IDMX again, not before this time.
    RetryAt(SystemTime),
    /// The fallback window has passed without an answer: hand over to SMTP.
    UseSmtp,
    /// The give-up time has passed: bounce.
    GiveUp,
}

impl RetryPolicy {
    /// Decides the next step after a temporary failure at `now`.
    ///
    /// `retry_after` is the receiver's lower bound for the next attempt;
    /// `jitter` is a random number in `-1.0..=1.0`.
    pub fn after_failure(
        &self,
        history: &History,
        now: SystemTime,
        retry_after: Option<Duration>,
        jitter: f64,
    ) -> Step {
        let elapsed = now
            .duration_since(history.first_attempt)
            .unwrap_or(Duration::ZERO);
        let may_fall_back = history.fallback == SmtpFallback::AfterWindow;

        if may_fall_back && elapsed >= self.fallback_window {
            return Step::UseSmtp;
        }
        if elapsed >= self.give_up {
            return Step::GiveUp;
        }

        let mut delay = self.delay(history.attempts, jitter);
        if may_fall_back {
            // Do not sleep past the moment SMTP becomes allowed.
            delay = delay.min(self.fallback_window.saturating_sub(elapsed));
        }
        Step::RetryAt(now + delay.max(retry_after.unwrap_or(Duration::ZERO)))
    }

    /// Delay after the `attempts`-th attempt: `first_delay` doubled per
    /// further attempt, capped at `max_delay`, then jittered by ±20 %.
    fn delay(&self, attempts: u32, jitter: f64) -> Duration {
        let doublings = attempts.saturating_sub(1).min(31);
        let base = self
            .first_delay
            .saturating_mul(1 << doublings)
            .min(self.max_delay);
        base.mul_f64(1.0 + JITTER * jitter.clamp(-1.0, 1.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINUTE: Duration = Duration::from_mins(1);
    const HOUR: Duration = Duration::from_hours(1);

    fn history(attempts: u32, fallback: SmtpFallback) -> History {
        History {
            first_attempt: SystemTime::UNIX_EPOCH,
            attempts,
            fallback,
        }
    }

    fn at(elapsed: Duration) -> SystemTime {
        SystemTime::UNIX_EPOCH + elapsed
    }

    #[test]
    fn after_failure_should_retry_after_one_minute_first() {
        let step = RetryPolicy::default().after_failure(
            &history(1, SmtpFallback::Never),
            at(Duration::ZERO),
            None,
            0.0,
        );

        assert_eq!(step, Step::RetryAt(at(MINUTE)));
    }

    #[test]
    fn after_failure_should_double_the_delay_per_attempt() {
        let step = RetryPolicy::default().after_failure(
            &history(4, SmtpFallback::Never),
            at(Duration::ZERO),
            None,
            0.0,
        );

        assert_eq!(step, Step::RetryAt(at(8 * MINUTE)));
    }

    #[test]
    fn after_failure_should_cap_the_delay_at_one_hour() {
        let step = RetryPolicy::default().after_failure(
            &history(20, SmtpFallback::Never),
            at(10 * HOUR),
            None,
            0.0,
        );

        assert_eq!(step, Step::RetryAt(at(11 * HOUR)));
    }

    #[test]
    fn after_failure_should_apply_twenty_percent_jitter() {
        let step = RetryPolicy::default().after_failure(
            &history(1, SmtpFallback::Never),
            at(Duration::ZERO),
            None,
            1.0,
        );

        assert_eq!(step, Step::RetryAt(at(Duration::from_secs(72))));
    }

    #[test]
    fn after_failure_should_treat_retry_after_as_lower_bound() {
        let step = RetryPolicy::default().after_failure(
            &history(1, SmtpFallback::Never),
            at(Duration::ZERO),
            Some(HOUR),
            0.0,
        );

        assert_eq!(step, Step::RetryAt(at(HOUR)));
    }

    #[test]
    fn after_failure_should_use_smtp_when_window_passed_without_answer() {
        let step = RetryPolicy::default().after_failure(
            &history(8, SmtpFallback::AfterWindow),
            at(2 * HOUR),
            None,
            0.0,
        );

        assert_eq!(step, Step::UseSmtp);
    }

    #[test]
    fn after_failure_should_not_use_smtp_when_receiver_answered_before() {
        let step = RetryPolicy::default().after_failure(
            &history(8, SmtpFallback::Never),
            at(3 * HOUR),
            None,
            0.0,
        );

        assert_eq!(step, Step::RetryAt(at(4 * HOUR)));
    }

    #[test]
    fn after_failure_should_not_sleep_past_the_end_of_the_window() {
        let step = RetryPolicy::default().after_failure(
            &history(7, SmtpFallback::AfterWindow),
            at(90 * MINUTE),
            None,
            0.0,
        );

        assert_eq!(step, Step::RetryAt(at(2 * HOUR)));
    }

    #[test]
    fn after_failure_should_give_up_after_five_days() {
        let step = RetryPolicy::default().after_failure(
            &history(130, SmtpFallback::Never),
            at(120 * HOUR),
            None,
            0.0,
        );

        assert_eq!(step, Step::GiveUp);
    }
}
