import asyncio
import logging
from typing import Coroutine, List

logger = logging.getLogger(__name__)


async def cancel_task(task):
    """Cancel the task safely"""
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass


async def wait_for_tasks(
    await_tasks: List[Coroutine], return_when=asyncio.FIRST_EXCEPTION
):
    """
    Method to run multiple tasks concurrently.
    return_when is used directly in the asyncio.wait call and sets the
    condition to cancel all running tasks and return.
    The arguments for it can be:
    asyncio.FIRST_COMPLETED, asyncio.FIRST_EXCEPTION or
    asyncio.ALL_COMPLETED
    check:
    https://docs.python.org/3/library/asyncio-task.html#waiting-primitives)

    Similar solutions for awaiting for several tasks can be found in:
    * https://python.plainenglish.io/how-to-manage-exceptions-when-waiting-on-multiple-asyncio-tasks-a5530ac10f02  # noqa: E501
    * https://stackoverflow.com/questions/63583822/asyncio-wait-on-multiple-tasks-with-timeout-and-cancellation  # noqa: E501

    """
    tasks = []

    for task in await_tasks:
        if not isinstance(task, asyncio.Task):
            task = asyncio.create_task(task)
        tasks.append(task)

    done, pending = await asyncio.wait(tasks, return_when=return_when)

    for task in pending:
        await cancel_task(task)

    for task in done:
        try:
            task.result()
        except Exception as e:
            logger.exception(e)
