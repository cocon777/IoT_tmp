"""Backward-compatible alias mapping `DeviceStub` to TV2's real `Device` model."""

from app.models.device import Device

DeviceStub = Device

__all__ = ["Device", "DeviceStub"]
