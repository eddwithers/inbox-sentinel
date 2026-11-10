"""Gmail query scoping must happen before any message body or model read."""
import asyncio

import pytest
from conftest import meta_response, ParsedBox


def test_query_scope_excludes_message_before_metadata_read(plugin, ctx, gmail):
    ctx.config['gmail_query'] = 'subject:DEMO-ONLY'
    gmail.respond('GET', '/users/me/messages', {'messages': []})
    asyncio.run(plugin._process(ctx, 'outside'))
    assert len(gmail.calls) == 1
    assert not ctx.llm.structured_calls
    assert not ctx.injected_messages


def test_query_scope_membership_requires_exact_id(plugin, ctx, gmail):
    ctx.config['gmail_query'] = 'subject:DEMO-ONLY'
    gmail.respond('GET', '/users/me/messages', {'messages': [{'id': 'different'}]})
    asyncio.run(plugin._process(ctx, 'outside'))
    assert len(gmail.calls) == 1


def test_query_scope_membership_paginates(plugin, ctx, gmail):
    ctx.config['gmail_query'] = 'subject:DEMO-ONLY'
    gmail.respond('GET', '/users/me/messages', {'messages': [{'id': 'other'}], 'nextPageToken': 'two'})
    gmail.respond('GET', '/users/me/messages', {'messages': [{'id': 'fixture'}]})
    gmail.respond('GET', '/users/me/messages/fixture', meta_response(label_ids=['CATEGORY_PROMOTIONS']))
    asyncio.run(plugin._process(ctx, 'fixture'))
    assert gmail.calls[2][1].endswith('/fixture')
    assert ('pageToken', 'two') in gmail.calls[1][2]
    assert not ctx.llm.structured_calls


def test_scope_search_failure_fails_closed(plugin, ctx, gmail):
    ctx.config['gmail_query'] = 'subject:DEMO-ONLY'
    gmail.respond('GET', '/users/me/messages', RuntimeError('search failed'))
    with pytest.raises(RuntimeError):
        asyncio.run(plugin._process(ctx, 'fixture'))
    assert not ctx.llm.structured_calls


def test_scope_page_limit_defers_without_read(plugin, ctx, gmail):
    ctx.config['gmail_query'] = 'in:inbox'
    for _ in range(5):
        gmail.respond('GET', '/users/me/messages', {'messages': [], 'nextPageToken': 'next'})
    with pytest.raises(RuntimeError, match='scope'):
        asyncio.run(plugin._process(ctx, 'fixture'))
    assert not ctx.llm.structured_calls
