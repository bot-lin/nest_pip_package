"""
Robot connection utilities.
"""

from __future__ import annotations

import importlib
import json
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Optional, Type
from urllib import error, request

import zenoh

if TYPE_CHECKING:  # pragma: no cover - type checking only
    from .ros2_types import Pose as PoseType
else:
    PoseType = object


@dataclass
class Robot:
    """
    Represents a robot that exposes a zenoh endpoint.
    """

    timeout: float = 5.0
    namespace: Optional[str] = field(default=None, init=False)
    last_error: Optional[str] = field(default=None, init=False)
    current_pose: Optional[PoseType] = field(default=None, init=False)
    _ip: Optional[str] = field(default=None, init=False, repr=False)
    _zenoh_session: Optional["zenoh.Session"] = field(default=None, init=False, repr=False)
    _pose_subscriber: Optional["zenoh.Subscriber"] = field(default=None, init=False, repr=False)
    _pose_type: Optional[Type[PoseType]] = field(default=None, init=False, repr=False)

    def connect(self, ip: str) -> bool:
        """
        Connect to the robot and return True if the expected zenoh namespace
        information is returned.
        """
        self._release_zenoh_resources()
        self.namespace = None
        self.last_error = None
        self.current_pose = None
        self._ip = None
        self._pose_type = None

        url = f"http://{ip}:5000/zenoh/zenoh"
        http_request = request.Request(url, method="GET")
        http_request.add_header("x-api-key", "1234567890")
        try:
            with request.urlopen(http_request, timeout=self.timeout) as response:
                if response.status != 200:
                    self.last_error = f"Unexpected status code: {response.status}"
                    return False
                payload = response.read()
        except error.HTTPError as exc:
            self.last_error = f"HTTP error {exc.code}: {exc.reason}"
            return False
        except error.URLError as exc:
            self.last_error = f"URL error: {exc.reason}"
            return False
        except TimeoutError:
            self.last_error = "Connection timed out"
            return False

        try:
            data = json.loads(payload)
        except json.JSONDecodeError as exc:
            preview = payload.decode("utf-8", errors="replace")[:200]
            if preview:
                self.last_error = (
                    f"Invalid JSON response ({preview!r}): {exc}"
                )
            else:
                self.last_error = f"Invalid JSON response: {exc}"
            return False

        if (
            isinstance(data, dict)
            and data.get("code") == 0
            and isinstance(data.get("data"), dict)
            and "namespace" in data["data"]
        ):
            self.namespace = data["data"]["namespace"]
            self._ip = ip
            return True

        self.last_error = "Unexpected response payload"
        return False

    def subscribe_pose(self) -> "zenoh.Subscriber":
        """
        Subscribe to the robot pose using zenoh and cache the latest Pose on the
        instance's current_pose attribute.
        """
        if self.namespace is None or self._ip is None:
            raise RuntimeError("Robot is not connected. Call connect() first.")
        if self._pose_subscriber is not None:
            return self._pose_subscriber

        session = self._ensure_session()
        key_expr = f"{self.namespace}/robot_pose"

        try:
            pose_type = self._resolve_pose_type()
        except RuntimeError as exc:
            self.last_error = str(exc)
            raise

        def _listener(sample: "zenoh.Sample") -> None:
            try:
                payload_bytes = (
                    sample.payload.to_bytes()
                    if hasattr(sample.payload, "to_bytes")
                    else bytes(sample.payload)
                )
            except Exception as exc:
                self.last_error = f"Failed to read pose payload: {exc}"
                return

            try:
                pose = pose_type.deserialize(payload_bytes)
            except Exception as exc:
                self.last_error = f"Failed to deserialize pose: {exc}"
                return

            self.current_pose = pose
            self.last_error = None

        subscriber = session.declare_subscriber(key_expr, _listener)
        self._pose_subscriber = subscriber
        return subscriber

    def unsubscribe_pose(self) -> None:
        """
        Stop receiving pose updates if currently subscribed.
        """
        if self._pose_subscriber is None:
            return

        try:
            self._pose_subscriber.undeclare()
        except Exception:
            pass
        finally:
            self._pose_subscriber = None

    def _ensure_session(self) -> "zenoh.Session":
        if self._zenoh_session is not None:
            return self._zenoh_session

        if self._ip is None:
            raise RuntimeError("Robot IP address unknown; connect first.")

        config = zenoh.Config()
        config.insert_json5("mode", '"client"')
        config.insert_json5(
            "connect/endpoints", f'["tcp/{self._ip}:7447"]'
        )

        try:
            self._zenoh_session = zenoh.open(config)
        except Exception as exc:
            self.last_error = f"Failed to open zenoh session: {exc}"
            raise RuntimeError(self.last_error) from exc

        return self._zenoh_session

    def _release_zenoh_resources(self) -> None:
        self.unsubscribe_pose()

        if self._zenoh_session is not None:
            try:
                self._zenoh_session.close()
            except Exception:
                pass
            finally:
                self._zenoh_session = None

    def _resolve_pose_type(self) -> Type[PoseType]:
        if self._pose_type is not None:
            return self._pose_type

        module_names = []
        if __package__:
            module_names.append(f"{__package__}.ros2_types")
        module_names.extend(["nest_zc.ros2_types", "ros2_types"])

        for module_name in module_names:
            try:
                module = importlib.import_module(module_name)
            except ImportError:
                continue

            pose_cls = getattr(module, "Pose", None)
            if pose_cls is not None:
                self._pose_type = pose_cls
                return pose_cls

        raise RuntimeError(
            "Pose type dependency not available. Install pycdr2 and ensure ros2_types.Pose is importable."
        )
