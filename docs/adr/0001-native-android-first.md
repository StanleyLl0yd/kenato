# ADR 0001: Native Android First

Status: Accepted

## Context

Kenato requires reliable audio routing, background calling behavior, notifications, Android power-management integration, Bluetooth handling, lock-screen behavior, and WebRTC integration.

Building Android and iOS simultaneously would multiply platform-specific VoIP work before the product protocol and call UX are stable.

## Decision

The first client will be native Android using Kotlin and Jetpack Compose.

iOS will follow after the Android protocol, encrypted messaging flow, and 1-to-1 call experience are stable.

## Consequences

Positive:

- direct access to Android platform APIs;
- fewer abstraction layers around audio/call lifecycle;
- easier performance and size optimization;
- one mobile platform to stabilize first.

Negative:

- iOS availability is delayed;
- shared UI code is intentionally not pursued.

Protocol compatibility remains platform-independent.
