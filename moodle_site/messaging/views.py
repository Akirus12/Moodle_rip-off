from __future__ import annotations

from datetime import datetime, time, timedelta

from django.contrib.auth import get_user_model
from django.contrib.auth.decorators import login_required, user_passes_test
from django.db.models import Q
from django.http import JsonResponse, Http404
from django.shortcuts import get_object_or_404, render
from django.utils import timezone

from core.models import Role, Message as SystemMessage, UserMessage as SystemUserMessage
from .models import DirectMessage, Broadcast, BroadcastRecipient

User = get_user_model()

def is_teacher_or_admin(user: User) -> bool:
    return user.role in {Role.TEACHER, Role.ADMINISTRATOR}

def _find_system_message_for_dm(dm: DirectMessage, body_value: str | None = None) -> SystemMessage | None:
    if body_value is None:
        body_value = dm.text

    return (
        SystemMessage.objects
        .filter(
            created_by=dm.sender,
            body=body_value,
            user_messages__user=dm.recipient,
        )
        .order_by("-created_at")
        .first()
    )


def _sync_delete_system_message_for_dm(dm: DirectMessage) -> None:
    sys_msg = _find_system_message_for_dm(dm)
    if not sys_msg:
        return

    # Delete only this user's delivery record
    SystemUserMessage.objects.filter(
        user=dm.recipient,
        message=sys_msg,
    ).delete()

    # If there are no more users tied to this system message, delete it too
    if not sys_msg.user_messages.exists():
        sys_msg.delete()


def _sync_edit_system_message_for_dm(dm: DirectMessage, old_text: str, new_text: str) -> None:
    sys_msg = _find_system_message_for_dm(dm, body_value=old_text)
    if not sys_msg:
        return

    sys_msg.body = new_text
    sys_msg.save(update_fields=["body"])


# ===== main page =====

@login_required
def messages_page(request):
    user = request.user
    contact_id = request.GET.get("contact")

    contacts = (
        User.objects.filter(is_active=True)
        .exclude(pk=user.pk)
        .order_by("username")
    )

    active_contact = None
    if contact_id:
        active_contact = get_object_or_404(User, pk=contact_id, is_active=True)
    elif contacts:
        active_contact = contacts[0]

    thread_messages: list[DirectMessage] = []
    if active_contact:
        now = timezone.now()

        outgoing_qs = DirectMessage.objects.filter(
            sender=user,
            recipient=active_contact,
            deleted_by_sender_at__isnull=True,
        )

        incoming_visible_qs = DirectMessage.objects.filter(
            sender=active_contact,
            recipient=user,
            deleted_by_recipient_at__isnull=True,
        ).filter(
            Q(scheduled_for__isnull=True) | Q(scheduled_for__lte=now)
        )

        thread_messages = (
            outgoing_qs
            | incoming_visible_qs
        ).select_related("sender", "recipient").order_by("created_at")

        unread_incoming = incoming_visible_qs.filter(is_read=False)
        if unread_incoming.exists():
            unread_ids = list(unread_incoming.values_list("id", flat=True))
            DirectMessage.objects.filter(
                id__in=unread_ids,
                is_read=False,
            ).update(is_read=True, read_at=now)

    context = {
        "contacts": contacts,
        "active_contact": active_contact,
        "messages": thread_messages,
        "is_teacher_or_admin": is_teacher_or_admin(user),
    }
    return render(request, "messages.html", context)


# ===== direct message send/edit/delete =====

@login_required
def send_message(request):
    """
    AJAX endpoint to send or schedule a direct message.

    POST:
      - recipient_id
      - text
      - is_scheduled: "0" or "1"
      - scheduled_for: "HH:MM" (only if is_scheduled == "1")
    """
    if request.method != "POST" or not request.headers.get("x-requested-with"):
        raise Http404

    user = request.user
    recipient_id = request.POST.get("recipient_id")
    raw_text = request.POST.get("text") or ""
    text = raw_text.strip()
    is_scheduled_flag = request.POST.get("is_scheduled") == "1"
    scheduled_for_str = (request.POST.get("scheduled_for") or "").strip()

    if not recipient_id or not text:
        return JsonResponse(
            {"ok": False, "error": "Recipient and text are required."},
            status=400,
        )

    recipient = get_object_or_404(User, pk=recipient_id, is_active=True)

    scheduled_for = None
    is_scheduled = False

    if is_scheduled_flag:
        if not scheduled_for_str:
            return JsonResponse(
                {"ok": False, "error": "Schedule time is required."},
                status=400,
            )
        try:
            parsed_time: time = datetime.strptime(scheduled_for_str, "%H:%M").time()
        except ValueError:
            return JsonResponse(
                {
                    "ok": False,
                    "error": "Invalid time format. Use HH:MM (e.g. 15:20).",
                },
                status=400,
            )

        today = timezone.localdate()
        naive_dt = datetime.combine(today, parsed_time)
        scheduled_for = timezone.make_aware(
            naive_dt,
            timezone.get_current_timezone(),
        )
        is_scheduled = True

    dm = DirectMessage.objects.create(
        sender=user,
        recipient=recipient,
        text=text,
        is_scheduled=is_scheduled,
        scheduled_for=scheduled_for,
    )

    subject = f"New message from {user.get_full_name() or user.username}"
    sys_msg = SystemMessage.objects.create(
        subject=subject,
        body=text,
        created_by=user,
        scheduled_for=scheduled_for,
        is_sent=True,
        target_role=None,
        target_course=None,
    )
    SystemUserMessage.objects.create(
        user=recipient,
        message=sys_msg,
    )

    # Время для отображения на клиенте
    if dm.scheduled_for:
        local_scheduled = timezone.localtime(dm.scheduled_for)
        at_display = local_scheduled.strftime("%H:%M")
    else:
        local_created = timezone.localtime(dm.created_at)
        at_display = local_created.strftime("%H:%M")

    return JsonResponse(
        {
            "ok": True,
            "id": dm.pk,
            "time": at_display,
        }
    )


@login_required
def edit_message(request, pk: int):
    """
    AJAX: edit your own message.

    POST:
      - text

    JSON:
      { ok, id, text, time, edited }
    """
    if request.method != "POST" or not request.headers.get("x-requested-with"):
        raise Http404

    dm = get_object_or_404(DirectMessage, pk=pk, sender=request.user)
    new_text = (request.POST.get("text") or "").strip()

    if not new_text:
        return JsonResponse({"ok": False, "error": "Empty text"}, status=400)

    # keep old text to locate the matching SystemMessage
    old_text = dm.text

    dm.text = new_text
    dm.edited_at = timezone.now()
    dm.save(update_fields=["text", "edited_at", "updated_at"])

    _sync_edit_system_message_for_dm(dm, old_text=old_text, new_text=new_text)

    return JsonResponse(
        {
            "ok": True,
            "id": dm.id,
            "text": dm.text,
            "time": timezone.localtime(dm.created_at).strftime("%H:%M"),
            "edited": True,
        }
    )

@login_required
def delete_message(request, pk: int):
    """
    AJAX: delete a message for BOTH sides.

    Only the sender is allowed to delete.
    """
    if request.method != "POST" or not request.headers.get("x-requested-with"):
        raise Http404

    dm = get_object_or_404(DirectMessage, pk=pk)

    # Only the sender can delete the message globally
    if request.user.pk != dm.sender_id:
        return JsonResponse({"ok": False, "error": "No permission"}, status=403)

    now = timezone.now()
    dm.deleted_by_sender_at = now
    dm.deleted_by_recipient_at = now
    dm.save(update_fields=["deleted_by_sender_at", "deleted_by_recipient_at"])

    _sync_delete_system_message_for_dm(dm)

    return JsonResponse({"ok": True, "id": dm.id})


# ===== broadcast =====

@login_required
@user_passes_test(is_teacher_or_admin)
def broadcast_message(request):
    """
    AJAX: teacher/admin sends the same text to many users.

    Expected POST:
      - text
      - recipients[]  (list of user IDs)
      - is_scheduled: "0" or "1" (optional)
      - scheduled_for: "HH:MM" (only if is_scheduled == "1")

    Behaviour:
      - Messages are always stored.
      - If scheduled_for is set, visibility to recipients is controlled
        by scheduled_for <= now in messages_page (same as direct messages).
    """
    if request.method != "POST" or not request.headers.get("x-requested-with"):
        raise Http404

    user = request.user
    raw_text = request.POST.get("text") or ""
    text = raw_text.strip()
    recipient_ids = request.POST.getlist("recipients[]")

    is_scheduled_flag = request.POST.get("is_scheduled") == "1"
    scheduled_for_str = (request.POST.get("scheduled_for") or "").strip()

    if not text or not recipient_ids:
        return JsonResponse(
            {"ok": False, "error": "Missing text or recipients"},
            status=400,
        )

    recipients_qs = (
        User.objects.filter(id__in=recipient_ids)
        .exclude(id=user.id)
        .distinct()
    )
    if not recipients_qs.exists():
        return JsonResponse({"ok": False, "error": "No valid recipients"}, status=400)

    scheduled_for = None
    is_scheduled = False

    if is_scheduled_flag:
        if not scheduled_for_str:
            return JsonResponse(
                {"ok": False, "error": "Schedule time is required."},
                status=400,
            )
        try:
            parsed_time: time = datetime.strptime(scheduled_for_str, "%H:%M").time()
        except ValueError:
            return JsonResponse(
                {
                    "ok": False,
                    "error": "Invalid time format. Use HH:MM (e.g. 15:20).",
                },
                status=400,
            )
        today = timezone.localdate()
        naive_dt = datetime.combine(today, parsed_time)
        scheduled_for = timezone.make_aware(
            naive_dt,
            timezone.get_current_timezone(),
        )
        is_scheduled = True

    broadcast = Broadcast.objects.create(
        sender=user,
        text=text,
        scheduled_for=scheduled_for,
        is_sent=True,
    )

    sys_subject = f"Broadcast from {user.get_full_name() or user.username}"
    sys_msg = SystemMessage.objects.create(
        subject=sys_subject,
        body=text,
        created_by=user,
        is_sent=True,
        scheduled_for=scheduled_for,
        target_role=None,
        target_course=None,
    )

    created_count = 0
    now = timezone.now()

    for u in recipients_qs:
        dm = DirectMessage.objects.create(
            sender=user,
            recipient=u,
            text=text,
            is_scheduled=is_scheduled,
            scheduled_for=scheduled_for,
            # is_delivered ignored for visibility
        )
        BroadcastRecipient.objects.create(
            broadcast=broadcast,
            user=u,
            direct_message=dm,
            delivered_at=now,
        )
        SystemUserMessage.objects.create(
            user=u,
            message=sys_msg,
        )
        created_count += 1

    return JsonResponse(
        {
            "ok": True,
            "broadcast_id": broadcast.id,
            "count": created_count,
        }
    )
