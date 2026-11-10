"""Attachment safety contracts using fictional MIME messages and no network."""
import asyncio
import base64
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
import importlib.util
from pathlib import Path

import pytest

from conftest import ParsedBox, TextBox, meta_response

pytestmark = pytest.mark.usefixtures("capture_notifications")


def message_with_attachment(*, text_attachment=False):
    msg = EmailMessage()
    msg['From'] = 'Bookings <bookings@example.test>'
    msg['To'] = 'customer@example.test'
    msg['Subject'] = 'Booking details'
    msg.set_content('Please see the attached booking details.')
    if text_attachment:
        msg.add_attachment('ATTACHMENT CONTENT MUST NOT BECOME THE BODY', filename='notes.txt')
        # Exercise the old first-text-part parser's failure on attachment-first MIME.
        parts = msg.get_payload()
        msg.set_payload([parts[1], parts[0]])
    else:
        msg.add_attachment(b'fictional document bytes', maintype='application',
                           subtype='pdf', filename='details.pdf')
    return msg


def test_mime_attachment_is_separate_from_body(plugin):
    msg = message_with_attachment(text_attachment=True)
    parsed = BytesParser(policy=policy.default).parsebytes(msg.as_bytes())
    content = plugin._extract_message_content(parsed)
    assert content['body'].strip() == 'Please see the attached booking details.'
    assert content['attachments'] == [{'filename': 'notes.txt', 'content_type': 'text/plain'}]
    assert 'ATTACHMENT CONTENT' not in content['body']


def test_plain_body_preferred_even_when_html_occurs_first(plugin):
    msg = EmailMessage()
    msg.set_content('<p>HTML variant</p>', subtype='html')
    msg.add_alternative('Plain variant', subtype='plain')
    content = plugin._extract_message_content(msg)
    assert content['body'].strip() == 'Plain variant'


def test_gmail_attached_document_never_invokes_drafter(plugin, ctx, gmail):
    ctx.config['delivery_target'] = 'session'
    msg = message_with_attachment()
    gmail.respond('GET', '/users/me/messages/fixture',
                  meta_response(sender=str(msg['From']), subject=str(msg['Subject'])))
    gmail.respond('GET', '/users/me/messages/fixture',
                  {'raw': base64.urlsafe_b64encode(msg.as_bytes()).decode()})
    ctx.llm.structured_result = ParsedBox({'verdict': 'IMPORTANT', 'summary': 'Booking details to review.'})
    ctx.llm.complete_result = TextBox("The attachment didn't come through. Please resend it.")
    asyncio.run(plugin._process(ctx, 'fixture'))
    assert not ctx.llm.complete_calls
    assert len(ctx.delivered_messages) == 1
    assert ctx.injected_messages == []
    alert = ctx.delivered_messages[0]
    assert 'not reviewed' in alert.lower()
    assert 'No reply drafted' in alert
    assert 'resend' not in alert.lower()
    assert 'No reply needed' not in alert


def test_imap_attachment_uses_same_safety_policy(plugin, ctx):
    spec = importlib.util.spec_from_file_location('attachment_imap_test',
                                                 Path(__file__).resolve().parents[1] / 'imap.py')
    assert spec is not None and spec.loader is not None
    imap = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(imap)
    imap._sentinel = plugin
    raw = message_with_attachment(text_attachment=True).as_bytes()

    class Client:
        def uid(self, command, uid, request):
            assert command == 'FETCH'
            if request == '(RFC822.SIZE)':
                return 'OK', [(b'fixture (RFC822.SIZE %d)' % len(raw),)]
            assert request == '(BODY.PEEK[]<0.262145>)'
            return 'OK', [(b'fixture', raw)]

    ctx.config['delivery_target'] = 'session'
    ctx.llm.structured_result = ParsedBox({'verdict': 'IMPORTANT', 'summary': 'Review booking details.'})
    ctx.llm.complete_result = TextBox('I have read the attachment and agree.')
    asyncio.run(imap._process_uid(ctx, Client(), 1))
    assert not ctx.llm.complete_calls
    assert len(ctx.delivered_messages) == 1
    assert ctx.injected_messages == []
    assert 'No reply drafted' in ctx.delivered_messages[0]
    assert 'I have read' not in ctx.delivered_messages[0]


@pytest.mark.parametrize('body', [
    'Please read the attached letter and confirm.',
    'See attachment for the details.',
    'The enclosed document explains the options.',
])
def test_body_reference_without_attachment_visibility_is_not_absence(plugin, ctx, body):
    ctx.llm.complete_result = TextBox('The file is missing; please resend.')
    draft = asyncio.run(plugin._draft_reply(ctx, 'bookings@example.test', 'Details', body))
    assert draft is None
    assert not ctx.llm.complete_calls
    assert ctx.state.get('budget_count', 0) == 0


def test_attachment_without_reference_still_blocks_draft(plugin, ctx):
    draft = asyncio.run(plugin._draft_reply(
        ctx, 'bookings@example.test', 'Details', 'Please confirm.',
        attachments=[{'filename': 'terms.pdf', 'content_type': 'application/pdf'}]))
    assert draft is None
    assert not ctx.llm.complete_calls


def test_truncated_body_does_not_get_a_reply_draft(plugin, ctx):
    ctx.config['delivery_target'] = 'session'
    ctx.llm.structured_result = ParsedBox({'verdict': 'IMPORTANT', 'summary': 'Long message to review.'})
    ctx.llm.complete_result = TextBox('I agree to everything.')
    asyncio.run(plugin._run_pipeline(
        ctx, mid_prefix='gmail', mid='long', sender='sender@example.test',
        subject='Long message', recipient='customer@example.test', reply_to='sender@example.test',
        label_ids=[], fetch_body=lambda: 'A' * 4100))
    assert not ctx.llm.complete_calls
    assert 'No reply drafted' in ctx.delivered_messages[0]


def test_empty_body_withholds_draft(plugin, ctx):
    assert asyncio.run(plugin._draft_reply(ctx, 'sender@example.test', 'Details', '')) is None
    assert not ctx.llm.complete_calls


def test_failed_body_read_is_retried_not_drafted(plugin, ctx):
    def fail():
        raise RuntimeError('fictional fetch failure')

    with pytest.raises(RuntimeError, match='fictional fetch failure'):
        asyncio.run(plugin._run_pipeline(
            ctx, mid_prefix='gmail', mid='failed', sender='sender@example.test',
            subject='Details', recipient='customer@example.test', reply_to='sender@example.test',
            label_ids=[], fetch_body=fail))
    assert not ctx.llm.complete_calls
    assert not ctx.llm.structured_calls
    assert not ctx.injected_messages


def test_test_tool_explains_attachment_draft_withheld(plugin, ctx):
    ctx.llm.structured_result = ParsedBox({'verdict': 'IMPORTANT', 'summary': 'Read document.'})
    result = asyncio.run(plugin._test(ctx, {
        'from': 'sender@example.test', 'subject': 'Details',
        'body': 'Please read the attached letter.', 'deliver': True}))
    assert result['suggested_reply'] is None
    assert 'not reviewed' in result['draft_withheld_reason']
    assert not ctx.llm.complete_calls
    assert len(ctx.delivered_messages) == 1
    assert ctx.injected_messages == []
    assert 'No reply drafted' in ctx.delivered_messages[0]


def test_body_only_reply_path_remains_available(plugin, ctx):
    ctx.llm.complete_result = TextBox('Yes, Tuesday at 10 works for me.')
    draft = asyncio.run(plugin._draft_reply(ctx, 'bookings@example.test', 'Time',
                                            'Would Tuesday at 10 work?'))
    assert draft == 'Yes, Tuesday at 10 works for me.'
    assert len(ctx.llm.complete_calls) == 1
