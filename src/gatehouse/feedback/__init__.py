"""Structured advisory feedback storage and reporting."""

from gatehouse.feedback.service import (
    FeedbackCapacityExceeded,
    FeedbackCategory,
    FeedbackCategoryValue,
    FeedbackComponent,
    FeedbackComponentValue,
    FeedbackRecord,
    FeedbackService,
    FeedbackSeverity,
    FeedbackSeverityValue,
    FeedbackState,
)

__all__ = [
    "FeedbackCapacityExceeded",
    "FeedbackCategory",
    "FeedbackCategoryValue",
    "FeedbackComponent",
    "FeedbackComponentValue",
    "FeedbackRecord",
    "FeedbackService",
    "FeedbackSeverity",
    "FeedbackSeverityValue",
    "FeedbackState",
]
