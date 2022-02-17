"""
This module contains methods for managing multiple asnycio tasks that are
supposed to run concurrently.
"""

import asyncio
import json
import logging
import os
from contextlib import suppress
from typing import Any, Awaitable, List

logger = logging.getLogger(__name__)


def load_from_env(variable, default=None):
    """Read values from the environment and try to convert values from json"""
    value = os.environ.get(variable, default)
    if value is not None:
        with suppress(json.decoder.JSONDecodeError, TypeError):
            value = json.loads(value)
    return value


async def cancel_task(task):
    """Cancel the task safely"""
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass


async def wait_till_finished(
    awaitables: List[Awaitable[Any]], finished_when=asyncio.FIRST_EXCEPTION
):
    """Run the tasks until one task is finished. The condition to finish
    depends on the argument 'finished_when', which directly translates
    to the asyncio.wait argument 'return_when' that can assume the following
    values: FIRST_COMPLETED, FIRST_EXCEPTION, ALL_COMPLETED
    (For more information regarding this, please check:
    https://docs.python.org/3/library/asyncio-task.html#waiting-primitives)

    All unfinished tasks will be cancelled.

    It can happen that multiple tasks finished at the same time.
    A MultiError is raised if at least one task finished with an exception.
    This exception wraps the exception of all tasks that finished with an
    exception.

    Return values of finished tasks are ignored. Use `asyncio.wait()` directly
    if you need access to the return values of tasks.

    If this function turns out to be useful it might be a good fit for
    `common/util` or `cc_utils`.

    """
    tasks = []

    # As of Python 3.8 `asyncio.wait()` should be called only with
    # `asyncio.Task`s.
    # See: https://docs.python.org/3/library/asyncio-task.html#asyncio-example-wait-coroutine # noqa: E501
    for awaitable in awaitables:
        if not isinstance(awaitable, asyncio.Task):
            awaitable = asyncio.create_task(awaitable)
        tasks.append(awaitable)

    done, pending = await asyncio.wait(tasks, return_when=finished_when)

    for task in pending:
        await cancel_task(task)

    errors = []
    for task in done:
        try:
            task.result()
        except Exception as ex:
            logger.exception(ex)
            errors.append(ex)

    if len(errors) == 1:
        raise errors[0]

    if errors:
        raise MultiError(errors)


class MultiError(Exception):
    """Exception used to raise multiple exceptions.

    The attribute `errors` gives access to the wrapper errors.

        try:
            something()
        except MultiError as e:
            for error in e.errors:
                if isinstance(e, ZeroDivisionError):
                    ...
                elif isinstance(e, AttributeError):
                    ...

    """

    def __init__(self, errors: List[Exception]):
        Exception.__init__(self)
        self.errors = errors
