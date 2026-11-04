from pydantic import BaseModel


class TaskInput(BaseModel):
    query: str


def process_query(item: TaskInput) -> dict:
    return {"echo": item.query.strip()}
