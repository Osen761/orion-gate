"""Concurrency helpers for safely running blocking connector work off the event loop."""

from __future__ import annotations

import asyncio
import contextvars
import functools
from collections.abc import Callable
from typing import Any, TypeVar


T = TypeVar("T")


async def run_sync_in_thread(func: Callable[..., T], /, *args: Any, **kwargs: Any) -> T:
    """Execute a synchronous callable in the default executor with an isolated ContextVar copy."""

    ctx = contextvars.copy_context()
    loop = asyncio.get_running_loop()
    bound = functools.partial(ctx.run, func, *args, **kwargs)
    return await loop.run_in_executor(None, bound)
