# messaging/models.py

from __future__ import annotations

from django.conf import settings
from django.db import models
from django.utils import timezone

from core.models import Course, Role  # reuse your existing core models


User = settings.AUTH_USER_MODEL


class DirectMessage(models.Model):
    """
    1:1 direct message between two users.

    This is what powers the chat UI:
    - sender / recipient
    - text
    - edited / scheduled flags
    - soft delete per side
    """
    sender = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name="sent_direct_messages",
    )
    recipient = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name="received_direct_messages",
    )

    # optional course context if you later want course-based chats
    course = models.ForeignKey(
        Course,
        on_delete=models.CASCADE,
        related_name="direct_messages",
        null=True,
        blank=True,
    )

    text = models.TextField()

    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    updated_at = models.DateTimeField(auto_now=True)
    edited_at = models.DateTimeField(null=True, blank=True)

    # scheduling (used by your "Schedule" wheel)
    is_scheduled = models.BooleanField(default=False, db_index=True)
    scheduled_for = models.DateTimeField(null=True, blank=True, db_index=True)
    is_delivered = models.BooleanField(
        default=True,
        db_index=True,
        help_text="False for scheduled messages not yet released (if you implement a scheduler).",
    )

    # read status from recipient point of view (optional, not used in UI yet)
    is_read = models.BooleanField(default=False, db_index=True)
    read_at = models.DateTimeField(null=True, blank=True)

    # soft delete per side
    deleted_by_sender_at = models.DateTimeField(null=True, blank=True)
    deleted_by_recipient_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        verbose_name = "Direct Message"
        verbose_name_plural = "Direct Messages"
        ordering = ["created_at"]
        indexes = [
            models.Index(fields=["sender", "recipient", "created_at"]),
            models.Index(fields=["recipient", "is_read", "created_at"]),
            models.Index(fields=["is_scheduled", "is_delivered", "scheduled_for"]),
        ]

    def __str__(self) -> str:
        return f"{self.sender} → {self.recipient}: {self.text[:30]}"

    # ---- helpers ----

    def mark_as_read(self, user) -> None:
        """Mark as read from the recipient side."""
        if user.pk == self.recipient_id and not self.is_read:
            self.is_read = True
            self.read_at = timezone.now()
            self.save(update_fields=["is_read", "read_at"])

    def soft_delete_for(self, user) -> None:
        """
        Soft-delete this message for one side.

        - For sender: sets deleted_by_sender_at
        - For recipient: sets deleted_by_recipient_at
        """
        now = timezone.now()
        if user.pk == self.sender_id and not self.deleted_by_sender_at:
            self.deleted_by_sender_at = now
            self.save(update_fields=["deleted_by_sender_at"])
        elif user.pk == self.recipient_id and not self.deleted_by_recipient_at:
            self.deleted_by_recipient_at = now
            self.save(update_fields=["deleted_by_recipient_at"])

    def is_visible_for(self, user) -> bool:
        """
        Check whether this message should be visible to the given user
        (respecting soft-delete flags).
        """
        if user.pk == self.sender_id:
            return self.deleted_by_sender_at is None
        if user.pk == self.recipient_id:
            return self.deleted_by_recipient_at is None
        return False


class Broadcast(models.Model):
    """
    Logical grouping for a "broadcast send" from teacher/admin
    to multiple users. The UI still creates individual DirectMessage
    rows for each recipient; this just tracks the broadcast itself.
    """
    sender = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name="direct_broadcasts",
    )
    text = models.TextField()

    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    # optional scheduling (not wired in JS yet, but available)
    scheduled_for = models.DateTimeField(null=True, blank=True, db_index=True)
    is_sent = models.BooleanField(default=True, db_index=True)

    # optional scoping to course/role if you ever want automatic recipient sets
    target_course = models.ForeignKey(
        Course,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="direct_broadcasts",
    )
    target_role = models.CharField(
        max_length=20,
        choices=Role.choices,
        null=True,
        blank=True,
    )

    class Meta:
        verbose_name = "Broadcast"
        verbose_name_plural = "Broadcasts"
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["scheduled_for", "is_sent"]),
            models.Index(fields=["target_course", "target_role"]),
        ]

    def __str__(self) -> str:
        return f"Broadcast #{self.id} by {self.sender}"


class BroadcastRecipient(models.Model):
    """
    Recipient of a Broadcast + link to the DirectMessage created
    for that user.
    """
    broadcast = models.ForeignKey(
        Broadcast,
        on_delete=models.CASCADE,
        related_name="recipients",
    )
    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name="direct_broadcast_receipts",
    )

    direct_message = models.ForeignKey(
        DirectMessage,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="broadcast_links",
    )

    delivered_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        verbose_name = "Broadcast Recipient"
        verbose_name_plural = "Broadcast Recipients"
        unique_together = [["broadcast", "user"]]
        indexes = [
            models.Index(fields=["broadcast", "user"]),
            models.Index(fields=["user", "delivered_at"]),
        ]

    def __str__(self) -> str:
        return f"Broadcast #{self.broadcast_id} → {self.user}"

    def mark_delivered(self, dm: DirectMessage | None = None) -> None:
        self.direct_message = dm
        self.delivered_at = timezone.now()
        self.save(update_fields=["direct_message", "delivered_at"])
