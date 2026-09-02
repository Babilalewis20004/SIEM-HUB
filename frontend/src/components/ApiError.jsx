// Renders the first failed mutation's API error (plus any validation
// `details` list the backend attached), or nothing if none have failed.
export default function ApiError({ mutations }) {
  const list = Array.isArray(mutations) ? mutations : [mutations];
  const failed = list.find((m) => m?.isError);
  if (!failed) return null;

  const data = failed.error?.response?.data;
  return (
    <p className="auth-error">
      {data?.error}
      {data?.details?.length > 0 && (
        <ul>{data.details.map((d) => <li key={d}>{d}</li>)}</ul>
      )}
    </p>
  );
}
