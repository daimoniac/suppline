import { describe, expect, it, vi, afterEach } from 'vitest';
import { cooldownDaysLeft, formatCooldown, formatHeld } from './utils';

const DAY = 24 * 60 * 60;

describe('cooldown helpers', () => {
  afterEach(() => vi.useRealTimers());

  it('counts a fresh digest (age 0) as held for the whole cooldown', () => {
    expect(cooldownDaysLeft(0, 7 * DAY)).toBe(7);
    expect(formatHeld(cooldownDaysLeft(0, 7 * DAY))).toBe('Held, 7d remaining');
  });

  it('moves the age recorded by the scan to now', () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2026-11-18T00:00:00Z'));
    const scannedAt = Date.parse('2026-11-16T00:00:00Z') / 1000;
    expect(cooldownDaysLeft(DAY, 7 * DAY, scannedAt)).toBe(4);
  });

  it('reports no cooldown and an ended one', () => {
    expect(cooldownDaysLeft(DAY, 0)).toBeNull();
    expect(formatHeld(null)).toBe('Held');
    expect(formatHeld(cooldownDaysLeft(8 * DAY, 7 * DAY))).toBe('Held, cooldown over');
  });

  it('formats remaining time', () => {
    expect(formatCooldown(3 * DAY + 4 * 3600)).toBe('3d 4h');
    expect(formatCooldown(2 * DAY)).toBe('2d');
    expect(formatCooldown(600)).toBe('1h');
  });
});
