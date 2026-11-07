from pydantic import BaseModel


class StatsResponse(BaseModel):
    captures: int
    hosts: int
    flows: int
    investigations: int
