import van from 'vanjs-core';

interface PasskeyPromptOptions {
  origin: string;
  rpId: string;
  requestId: string;
  continueWithoutPsst(): void;
}

export interface PasskeyPrompt {
  close(): void;
  focusContinue(): void;
  showStatus(message: string): void;
}

const css = `
  :host {
    all: initial;
    color-scheme: light dark;
  }
  dialog {
    border: 1px solid GrayText;
    border-radius: 0.5rem;
    box-shadow: 0 0.5rem 1.5rem rgb(0 0 0 / 25%);
    font: 0.875rem/1.5 system-ui, sans-serif;
    inset: 1rem 1rem auto auto;
    margin: 0;
    max-width: min(24rem, calc(100vw - 2rem));
    padding: 1rem;
    position: fixed;
    z-index: 2147483647;
  }
  h2 { margin: 0 0 0.5rem; }
  p { margin: 0 0 0.75rem; }
  label { display: grid; gap: 0.25rem; margin-block: 1rem; }
  input, button { font: inherit; }
  input {
    box-sizing: border-box;
    padding: 0.5rem;
    width: 100%;
  }
  footer { margin-top: 1rem; }
  button {
    cursor: pointer;
    padding: 0.5rem 0.75rem;
  }
`;

/**
 * Presents the accessible handoff state for one page-level passkey request.
 */
export const showPasskeyPrompt = ({
  origin,
  rpId,
  requestId,
  continueWithoutPsst,
}: PasskeyPromptOptions): PasskeyPrompt => {
  const status = van.state(
    'Run psst passkey handoff SESSION_REFERENCE with this browser request ID.',
  );
  const {button, code, dialog, footer, h2, input, label, output, p, style} = van.tags;
  const continueButton = button(
    {type: 'button', onclick: continueWithoutPsst},
    'Continue without psst',
  );
  const prompt = dialog(
    {
      open: true,
      'aria-labelledby': 'psst-passkey-title',
      onkeydown: (event: KeyboardEvent) => {
        if (event.key !== 'Escape') {
          return;
        }

        event.preventDefault();
        continueWithoutPsst();
      },
    },
    h2({id: 'psst-passkey-title'}, 'Waiting for psst'),
    p('A passkey was requested by ', code(origin), ` for ${rpId}.`),
    label('Browser request ID', input({type: 'text', readOnly: true, value: requestId})),
    output(status),
    footer(continueButton),
  );

  const host = document.createElement('psst-passkey-request');
  const shadow = host.attachShadow({mode: 'closed'});
  van.add(shadow, style(css), prompt);
  document.documentElement.append(host);

  const previousFocus =
    document.activeElement instanceof HTMLElement ? document.activeElement : undefined;
  continueButton.focus();

  return {
    close: () => {
      host.remove();
      if (previousFocus?.isConnected) {
        previousFocus.focus();
      }
    },
    focusContinue: () => continueButton.focus(),
    showStatus: message => {
      status.val = message;
    },
  };
};
