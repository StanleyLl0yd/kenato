# Kenato Brand

## Identity

Name: **Kenato**  
Primary wordmark: **kenato**  
Primary tagline: **Talk freely.**  
Descriptor: **Private calls & messages**  
Visual direction: **Zen Minimal**

## Brand character

Kenato is calm, light, modern, private, friendly, and trustworthy.

The product should not visually present itself as a military, hacker, cyberpunk, or fear-driven security tool.

Japanese influence is subtle and comes from restraint, balance, whitespace, rhythm, and clean geometry rather than literal cultural motifs.

## Brand principles

1. Human before technical.
2. Private without looking paranoid.
3. Simple before feature-rich.
4. Calm before flashy.
5. Explain security; do not market fear.
6. One recognizable symbol.
7. No unnecessary visual noise.

## Logo direction

The symbol is based on two soft forms facing each other, representing:

- two people;
- conversation;
- two halves of a connection;
- a quiet voice/sound motif;
- negative space as the channel between them.

Avoid phone receivers, padlocks, shields, chat bubbles as the primary identity, or a generic letter K in a circle.

## Core palette

### Light

- Warm Ivory: `#FAF8F3`
- Ink Indigo: `#4E5BD9`
- Ink Indigo 600: `#414CC0`
- Ink Indigo 700: `#353F9F`
- Mist Blue: `#EAF0F8`
- Soft Aqua: `#58B6B2`
- Soft Coral: `#E98A7A`
- Text Primary: `#16171C`
- Text Secondary: `#5A5E57`

### Dark

- Night 950: `#0F1115`
- Night 900: `#14171D`
- Night 800: `#1B2028`
- Dark Indigo: `#6C78F0`
- Text Primary: `#F3F4F6`
- Text Secondary: `#C7CBD2`

## Typography

Primary UI font: **Inter**

Initial weights:

- 400 Regular
- 500 Medium
- 600 SemiBold
- 700 Bold

The implementation must not bundle unnecessary font assets when equivalent platform/runtime delivery is possible.

## Geometry

Primary screen horizontal padding: **24 dp**

Spacing scale:

`4, 8, 12, 16, 20, 24, 32, 40, 48, 56, 64`

Radii:

`6, 8, 12, 16, 20, 24, full`

Main CTA:

- height: 56 dp;
- radius: 18 dp.

Common card radius: 20–24 dp.

Minimum touch target: 48 × 48 dp.

## App icon

The owner-approved icon is now canonical and supersedes earlier conceptual icon directions.

Its visual identity is:

- warm-white rounded-square surface with subtle depth/shadow;
- two soft opposing forms;
- left form in deep navy/indigo;
- right form in pale mist blue;
- central negative space expressing a quiet connection;
- no text, phone receiver, padlock, shield, or chat bubble.

Canonical source identity:

- dimensions: 1254 × 1254 px;
- SHA-256: `9a60ea3c539c4299ccd5ec2ff303f2813e7f152398b6259ffd41f022426d90da`.

The canonical artwork must not be re-encoded, redrawn, vectorized, recolored, cropped, recompressed, optimized in place, or replaced without an explicit owner decision.

Platform-specific derivatives are separate assets. The current Android launcher derivative is documented in `branding/icon/README.md`.

Adaptive/themed/monochrome variants must not be fabricated by automatic background removal. They require a separately reviewed brand derivative.

## Tone of voice

Copy is short, calm, factual, and human.

Preferred:

- Calling…
- Connecting…
- Invite ready
- Contact added securely
- Couldn't connect the call
- Try again

Avoid exposing implementation language or security theatre in normal UI.

## Store baseline

Title: **Kenato**

English descriptor:

> Private calls & messages

Russian descriptor:

> Приватные звонки и сообщения

English short positioning:

> Private 1-to-1 calls and encrypted messaging without phone numbers.

Russian short positioning:

> Приватные звонки один на один и зашифрованные сообщения без номера телефона.

## UI baseline

Top-level product model for 1.0:

- People
- contact conversation/call surface
- Settings

The call screen is intentionally centered, spacious, and minimal. The interface should prioritize the person and the call state rather than network or cryptographic implementation details.
