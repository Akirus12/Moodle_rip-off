# messaging/views.py

from __future__ import annotations

import datetime

from django.contrib.auth import get_user_model
from django.contrib.auth.decorators import login_required, user_passes_test
from django.db.models import Q
from django.http import JsonResponse, Http404
from django.shortcuts import get_object_or_404, render
from django.utils import timezone

from datetime import datetime, time, timedelta

from core.models import Role  # from your core app
from .models import DirectMessage, Broadcast, BroadcastRecipient

User = get_user_model()

def is_teacher_or_admin(user: User) -> bool:
    return user.role in {Role.TEACHER, Role.ADMINISTRATOR}

@login_required
def messages_page(request):
    """
    Render the chat UI.

    Contacts: all active users except self.
    Thread:
      - current user always sees their own messages (incl. scheduled in the future)
      - other side sees scheduled messages only when scheduled_for <= now
    """
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

    thread_messages = []
    if active_contact:
        now = timezone.now()

        thread_messages = (
            DirectMessage.objects.filter(
                # Messages I sent to them (including scheduled ones)
                (
                    Q(sender=user, recipient=active_contact)
                    & Q(deleted_by_sender_at__isnull=True)
                )
                |
                # Messages they sent to me:
                # - normal (not scheduled), OR
                # - scheduled and time has come (scheduled_for <= now)
                (
                    Q(sender=active_contact, recipient=user)
                    & Q(deleted_by_recipient_at__isnull=True)
                    & (
                        Q(is_scheduled=False)
                        | Q(is_scheduled=True, scheduled_for__lte=now)
                    )
                )
            )
            .select_related("sender", "recipient")
            .order_by("created_at")
        )

    context = {
        "contacts": contacts,
        "active_contact": active_contact,
        "messages": thread_messages,
        "is_teacher_or_admin": is_teacher_or_admin(user),
    }
    return render(request, "messages.html", context)

@login_required
def send_message(request):
    """
    AJAX endpoint to send or schedule a direct message.

    POST params:
      - recipient_id
      - text
      - is_scheduled: "0" or "1"
      - scheduled_for: "HH:MM" (only if is_scheduled == "1")
    """
    if request.method != "POST" or not request.headers.get("x-requested-with"):
        raise Http404

    user = request.user
    recipient_id = request.POST.get("recipient_id")
    text = (request.POST.get("text") or "").strip()
    is_scheduled_flag = request.POST.get("is_scheduled") == "1"
    scheduled_for_str = (request.POST.get("scheduled_for") or "").strip()

    if not recipient_id or not text:
        return JsonResponse(
            {"ok": False, "error": "Recipient and text are required."},
            status=400,
        )

    recipient = get_object_or_404(User, pk=recipient_id, is_active=True)

    # --- parse and build scheduled_for datetime (if requested) ---
    scheduled_for = None
    if is_scheduled_flag:
        if not scheduled_for_str:
            return JsonResponse(
                {"ok": False, "error": "Schedule time is required."},
                status=400,
            )

        # Expect strict HH:MM in 24h format (e.g. "15:20")
        try:
            parsed_time: time = datetime.strptime(
                scheduled_for_str, "%H:%M"
            ).time()
        except ValueError:
            return JsonResponse(
                {
                    "ok": False,
                    "error": "Invalid time format. Use HH:MM (e.g. 15:20).",
                },
                status=400,
            )

        # Build naive datetime for *today* at that time
        today = timezone.localdate()
        naive_dt = datetime.combine(today, parsed_time)

        # Make it aware in the current time zone
        aware_dt = timezone.make_aware(
            naive_dt,
            timezone.get_current_timezone(),
        )

        # If it's already in the past, schedule for tomorrow
        if aware_dt <= timezone.now():
            aware_dt += timedelta(days=1)

        scheduled_for = aware_dt

    # --- create the message ---
    msg = DirectMessage.objects.create(
        sender=user,
        recipient=recipient,
        text=text,
        is_scheduled=bool(scheduled_for),
        scheduled_for=scheduled_for,
    )

    # Time label to return to frontend
    if msg.is_scheduled and msg.scheduled_for:
        local_scheduled = timezone.localtime(msg.scheduled_for)
        at_display = local_scheduled.strftime("%H:%M")
    else:
        local_created = timezone.localtime(msg.created_at)
        at_display = local_created.strftime("%H:%M")

    return JsonResponse(
        {
            "ok": True,
            "id": msg.pk,
            "time": at_display,
        }
    )

@login_required
def edit_message(request, pk: int):
    """
    AJAX: edit your own message.

    POST fields:
    - text

    JSON: { ok, id, text, time, edited }
    """
    if request.method != "POST" or not request.headers.get("x-requested-with"):
        raise Http404

    msg = get_object_or_404(DirectMessage, pk=pk, sender=request.user)
    new_text = (request.POST.get("text") or "").strip()

    if not new_text:
        return JsonResponse({"ok": False, "error": "Empty text"}, status=400)

    msg.text = new_text
    msg.edited_at = timezone.now()
    msg.save(update_fields=["text", "edited_at", "updated_at"])

    return JsonResponse(
        {
            "ok": True,
            "id": msg.id,
            "text": msg.text,
            "time": msg.created_at.strftime("%H:%M"),
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

    msg = get_object_or_404(DirectMessage, pk=pk)

    # Only the sender can delete the message globally
    if request.user.pk != msg.sender_id:
        return JsonResponse({"ok": False, "error": "No permission"}, status=403)

    now = timezone.now()
    msg.deleted_by_sender_at = now
    msg.deleted_by_recipient_at = now
    msg.save(update_fields=["deleted_by_sender_at", "deleted_by_recipient_at"])

    return JsonResponse({"ok": True, "id": msg.id})

@login_required
@user_passes_test(is_teacher_or_admin)
def broadcast_message(request):
    """
    AJAX: teacher/admin sends the same text to many users.

    Expected POST:
    - text
    - recipients[]  (list of user IDs)

    JSON:
    { ok, error?, broadcast_id, count }
    """
    if request.method != "POST" or not request.headers.get("x-requested-with"):
        raise Http404

    text = (request.POST.get("text") or "").strip()
    recipient_ids = request.POST.getlist("recipients[]")

    if not text or not recipient_ids:
        return JsonResponse(
            {"ok": False, "error": "Missing text or recipients"},
            status=400,
        )

    recipients_qs = (
        User.objects.filter(id__in=recipient_ids)
        .exclude(id=request.user.id)
        .distinct()
    )

    if not recipients_qs.exists():
        return JsonResponse({"ok": False, "error": "No valid recipients"}, status=400)

    broadcast = Broadcast.objects.create(sender=request.user, text=text)
    now = timezone.now()
    created_count = 0

    for u in recipients_qs:
        dm = DirectMessage.objects.create(
            sender=request.user,
            recipient=u,
            text=text,
            created_at=now,
            is_delivered=True,
        )
        BroadcastRecipient.objects.create(
            broadcast=broadcast,
            user=u,
            direct_message=dm,
            delivered_at=now,
        )
        created_count += 1

    return JsonResponse(
        {
            "ok": True,
            "broadcast_id": broadcast.id,
            "count": created_count,
        }
    )
