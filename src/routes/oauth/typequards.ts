export interface UserData {
  sub: string;
  name: string;
  given_name: string;
  family_name: string;
  picture: string;
  email: string;
  email_verified: boolean;
  locale: string;
}
export interface ErrorResponse {
  error: string;
  error_description: string;
}

export function isUserData(data: unknown): data is UserData {
  return (
    typeof data === 'object' &&
    data != null &&
    'sub' in data &&
    'name' in data &&
    'given_name' in data &&
    'family_name' in data &&
    'picture' in data &&
    'email' in data &&
    'email_verified' in data &&
    'locale' in data
  );
}

export function isErrorResponse(data: unknown): data is ErrorResponse {
  return (
    typeof data === 'object' &&
    data != null &&
    'error' in data &&
    'error_description' in data
  );
}
