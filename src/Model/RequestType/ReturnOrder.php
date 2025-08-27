<?php

/**
 * See LICENSE.md for license details.
 */

declare(strict_types=1);

namespace Dhl\Sdk\Paket\Retoure\Model\RequestType;

class ReturnOrder implements \JsonSerializable
{
    public const DOCUMENT_TYPE_PDF = 'SHIPMENT_LABEL';
    public const DOCUMENT_TYPE_QR = 'QR_LABEL';
    public const DOCUMENT_TYPE_BOTH = 'BOTH';

    /**
     * @var string
     */
    private $receiverId;

    /**
     * @var SimpleAddress
     */
    private $shipper;

    /**
     * @var string|null
     */
    private $customerReference;

    /**
     * @var string|null
     */
    private $shipmentReference;

    /**
     * @var string|null $returnDocumentType The type of document(s) to return [SHIPMENT_LABEL, QR_LABEL, BOTH]
     */
    private $returnDocumentType;

    /**
     * @var string|null
     */
    private $email;

    /**
     * @var string|null
     */
    private $phone;

    /**
     * @var float|null
     */
    private $value;

    /**
     * @var int|null
     */
    private $weightInGrams;

    /**
     * @var CustomsDocument|null
     */
    private $customsDocument;

    public function __construct(
        string $receiverId,
        SimpleAddress $senderAddress
    ) {
        $this->receiverId = $receiverId;
        $this->shipper = $senderAddress;
    }

    public function setCustomerReference(?string $customerReference): self
    {
        $this->customerReference = $customerReference;

        return $this;
    }

    public function setShipmentReference(?string $shipmentReference): self
    {
        $this->shipmentReference = $shipmentReference;

        return $this;
    }

    public function setReturnDocumentType(?string $returnDocumentType): self
    {
        $this->returnDocumentType = $returnDocumentType;

        return $this;
    }

    public function setEmail(?string $email): self
    {
        $this->email = $email;

        return $this;
    }

    public function setPhone(?string $phone): self
    {
        $this->phone = $phone;

        return $this;
    }

    public function setValue(?float $value): self
    {
        $this->value = $value;

        return $this;
    }

    public function setWeightInGrams(?int $weightInGrams): self
    {
        $this->weightInGrams = $weightInGrams;

        return $this;
    }

    public function setCustomsDocument(?CustomsDocument $customsDocument): self
    {
        $this->customsDocument = $customsDocument;

        return $this;
    }

    /**
     * Specify data which should be serialized to JSON
     *
     * @return mixed[] Serializable object properties
     */
    public function jsonSerialize(): array
    {
        return get_object_vars($this);
    }
}
