from datetime import datetime
import json


TRACE_PREFIX = "AGENT_TRACE "


class TraceRecorder:
    def __init__(self, enabled=True):
        self.enabled = enabled
        self.events = []

    def emit(self, stage, tool, message, **data):
        event = {
            "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "stage": stage,
            "tool": tool,
            "message": message,
            "data": data,
        }
        self.events.append(event)
        if self.enabled:
            print(TRACE_PREFIX + json.dumps(event, ensure_ascii=False), flush=True)
        return event

