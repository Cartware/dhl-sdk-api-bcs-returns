<?php
namespace Dhl\Sdk\Paket\Retoure\Http\Authentication;

use Http\Discovery\HttpClientDiscovery;
use Http\Message\Authentication;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Log\LoggerInterface;

class OAuth2 implements Authentication
{
    public const URL_AUTH_PRODUCTION = 'https://api-eu.dhl.com/parcel/de/account/auth/ropc/v1/token';

    public const URL_AUTH_SANDBOX = 'https://api-sandbox.dhl.com/parcel/de/account/auth/ropc/v1/token';

    /**
     * @var string
     */
    private string $username;

    /**
     * @var string
     */
    private string $password;

    /**
     * @var string
     */
    private string $clientId;

    /**
     * @var string
     */
    private string $clientSecret;

    /**
     * @var string|null
     */
    private ?string $accessToken = null;

    /**
     * @var int|null
     */
    private ?int $expiresAt = null;

    /**
     * @var ClientInterface|null
     */
    private ?ClientInterface $client = null;

    /**
     * @var LoggerInterface|null
     */
    private ?LoggerInterface $logger = null;

    private bool $sandboxMode = false;

    public function __construct(
        string $username,
        string $password,
        string $clientId,
        string $clientSecret,
        bool $sandboxMode = false,
        ClientInterface $client = null,
        LoggerInterface $logger = null
    ) {
        $this->username = $username;
        $this->password = $password;
        $this->clientId = $clientId;
        $this->clientSecret = $clientSecret;
        $this->sandboxMode = $sandboxMode;
        if ($client === null) {
            $client = HttpClientDiscovery::find();
        }
        $this->client = $client;
    }

    public function authenticate(RequestInterface $request)
    {
        if (!$this->accessToken || time() >= $this->expiresAt) {
            $this->fetchAccessToken();
        }

        if ($this->accessToken) {
            return $request->withHeader('Authorization', 'Bearer ' . $this->accessToken);
        }

        return $request;
    }

    /**
     * @throws \JsonException
     * @throws \RuntimeException
     */
    private function fetchAccessToken(): void
    {
        if ($this->logger !== null) {
            $this->logger->info('OAuth2 - Fetching access token');
        }

        $tokenUrl = $this->sandboxMode
            ? self::URL_AUTH_SANDBOX
            : self::URL_AUTH_PRODUCTION;

        $response = $this->client->sendRequest(new \GuzzleHttp\Psr7\Request(
            'POST',
            $tokenUrl,
            ['Content-Type' => 'application/x-www-form-urlencoded'],
            http_build_query([
                'grant_type'    => 'password',
                'client_id'     => $this->clientId,
                'client_secret' => $this->clientSecret,
                'username'      => $this->username,
                'password'      => $this->password
            ])
        ));

        if ($this->logger !== null) {
            $this->logger->info('OAuth2 - Access token result: ' . $response->getStatusCode());
        }

        try {
            $data = json_decode((string)$response->getBody(), true, 512, JSON_THROW_ON_ERROR);
            if (!isset($data['access_token'])) {
                throw new \RuntimeException('Failed to fetch OAuth2 token');
            }
        } catch (\JsonException | \RuntimeException $e) {
            $this->accessToken = null;
            $this->expiresAt = null;

            if ($this->logger !== null) {
                $this->logger->error('OAuth2 - ' . $e->getMessage());
            }

            throw $e;
        }

        $this->accessToken = $data['access_token'];
        $this->expiresAt = time() + ($data['expires_in'] ?? 3600);
    }
}
