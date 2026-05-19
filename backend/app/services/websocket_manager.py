from collections import defaultdict
from fastapi import WebSocket


class WebSocketManager:
    def __init__(self) -> None:
        self.connections: dict[int, list[WebSocket]] = defaultdict(list)

    async def connect(self, scan_id: int, websocket: WebSocket) -> None:
        await websocket.accept()
        self.connections[scan_id].append(websocket)

    def disconnect(self, scan_id: int, websocket: WebSocket) -> None:
        if websocket in self.connections[scan_id]:
            self.connections[scan_id].remove(websocket)

    async def broadcast(self, scan_id: int, payload: dict) -> None:
        for websocket in list(self.connections[scan_id]):
            try:
                await websocket.send_json(payload)
            except Exception:
                self.disconnect(scan_id, websocket)


ws_manager = WebSocketManager()

