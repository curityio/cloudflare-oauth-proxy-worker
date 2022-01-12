export default class Configuration {
    private readonly _trustedOrigins: string[]
    private readonly _trustedOriginsString: string
    private readonly _cookieNamePrefix: string
    private readonly _encryptionKey: string

    constructor(trustedOrigins: string, cookieNamePrefix: string, encryptionKey: string) {
        this._trustedOriginsString = trustedOrigins
        this._trustedOrigins = trustedOrigins.split(",")
        this._cookieNamePrefix = cookieNamePrefix
        this._encryptionKey = encryptionKey
    }

    get trustedOrigins(): string[] {
        return this._trustedOrigins
    }

    get trustedOriginsString(): string {
        return this._trustedOriginsString
    }

    get cookieNamePrefix(): string {
        return this._cookieNamePrefix
    }

    get encryptionKey(): string {
        return this._encryptionKey
    }
}
