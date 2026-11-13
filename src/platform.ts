/** System webviews expose the host platform without another native round trip. */
export const isMac = /Mac|iPhone|iPad|iPod/i.test(navigator.platform);
export const isWindows = /Win/i.test(navigator.platform);
/** Only macOS has iOS simulators; Windows and Linux run Android emulators alone. */
export const androidOnly = !isMac;
export const commandKey = isMac ? '⌘' : 'Ctrl';
/** The same modifier spelled out, for the descriptions a screen reader reads. */
export const commandKeyName = isMac ? 'Command' : 'Control';

export function shortcut(key: string, shift = false): string {
  return `${commandKey}${shift ? isMac ? ' ⇧' : ' Shift' : ''} ${key}`;
}
