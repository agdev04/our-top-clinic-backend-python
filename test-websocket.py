import asyncio
import websockets

async def test_websocket():
    uri = "ws://localhost:3007/ws/presence/1"
    async with websockets.connect(uri) as websocket:
        # Send join message
        await websocket.send('{"user_id": "123", "action": "join"}')
        # Receive updates
        while True:
            response = await websocket.recv()
            print(f"Received: {response}")

# Run the test
asyncio.get_event_loop().run_until_complete(test_websocket())