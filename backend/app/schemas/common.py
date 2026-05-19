from pydantic import BaseModel


class Page(BaseModel):
    total: int
    items: list

