export class MissingAPIKeyError extends Error {
  constructor (message: string) {
    super();
    this.name = 'MissingAPIKeyError';
    this.message = message;
  }
}

export class MissingContactEmailError extends Error {
  constructor (message: string) {
    super();
    this.name = 'MissingContactEmailError';
    this.message = message;
  }
}

export class InvalidInputError extends Error {
  constructor (message: string) {
    super();
    this.name = 'InvalidInputError';
    this.message = message;
  }
}

export class NoDetectionServiceError extends Error {
  constructor (message: string) {
    super();
    this.name = 'NoDetectionServiceError';
    this.message = message;
  }
}

export class NoImplementationError extends Error {
  constructor (message: string) {
    super();
    this.name = 'NoImplementationError';
    this.message = message;
  }
}

export class InvalidParsedAddressError extends Error {
  constructor (message: string) {
    super();
    this.name = 'InvalidParsedAddressError';
    this.message = message;
  }
}

export class UnroutableAddressError extends Error {
  constructor (message: string) {
    super();
    this.name = 'UnroutableAddressError';
    this.message = message;
  }
}

export class RecordNotFoundError extends Error {
  constructor (message: string) {
    super();
    this.name = 'RecordNotFoundError';
    this.message = message;
  }
}

export class SaveFailureError extends Error {
  constructor (message: string) {
    super();
    this.name = 'SaveFailureError';
    this.message = message;
  }
}

export class BannedError extends Error {
  constructor (message: string) {
    super();
    this.name = 'BannedError';
    this.message = message;
  }
}

export class MaintenanceError extends Error {
  constructor (message: string) {
    super();
    this.name = 'MaintenanceError';
    this.message = message;
  }
}

export class UnknownServiceError extends Error {
  constructor (message: string) {
    super();
    this.name = 'UnknownServiceError';
    this.message = message;
  }
}

export class MissingFieldError extends Error {
  constructor (message: string) {
    super();
    this.name = 'MissingFieldError';
    this.message = message;
  }
}

export class RateLimitError extends Error {
  constructor (message: string) {
    super();
    this.name = 'RateLimitError';
    this.message = message;
  }
}
