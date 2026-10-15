interface Props {
  tone: 'error' | 'warn' | 'info' | 'ok';
  title: string;
  detail?: string;
  action?: { label: string; onClick: () => void; busy?: boolean };
  onDismiss?: () => void;
}

export default function Banner({ tone, title, detail, action, onDismiss }: Props) {
  return (
    <div className={`banner banner--${tone}`} role={tone === 'error' ? 'alert' : 'status'}>
      <div className="banner__text">
        <strong>{title}</strong>
        {detail ? <span className="banner__detail">{detail}</span> : null}
      </div>
      <div className="banner__actions">
        {action ? (
          <button type="button" className="btn btn--small" onClick={action.onClick} disabled={action.busy}>
            {action.label}
          </button>
        ) : null}
        {onDismiss ? (
          <button type="button" className="btn btn--small btn--ghost" onClick={onDismiss} aria-label="Dismiss">
            Dismiss
          </button>
        ) : null}
      </div>
    </div>
  );
}
