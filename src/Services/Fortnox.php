<?php

namespace KFoobar\Fortnox\Services;

use KFoobar\Fortnox\Services\Client;
use KFoobar\Fortnox\Resources\Unit\Units;
use KFoobar\Fortnox\Resources\Inbox\Inboxes;
use KFoobar\Fortnox\Resources\Account\Accounts;
use KFoobar\Fortnox\Resources\Invoice\Invoices;
use KFoobar\Fortnox\Resources\Price\PriceLists;
use KFoobar\Fortnox\Resources\Project\Projects;
use KFoobar\Fortnox\Resources\Voucher\Vouchers;
use KFoobar\Fortnox\Resources\Customer\Customers;
use KFoobar\Fortnox\Resources\Supplier\Suppliers;
use KFoobar\Fortnox\Resources\Currency\Currencies;
use KFoobar\Fortnox\Resources\Terms\TermsOfPayments;
use KFoobar\Fortnox\Resources\Voucher\VoucherSeries;
use KFoobar\Fortnox\Resources\CostCenter\CostCenters;
use KFoobar\Fortnox\Resources\Invoice\InvoiceAccruals;
use KFoobar\Fortnox\Resources\Invoice\InvoicePayments;
use KFoobar\Fortnox\Resources\Template\PrintTemplates;
use KFoobar\Fortnox\Resources\Terms\TermsOfDeliveries;
use KFoobar\Fortnox\Resources\Supplier\SupplierInvoices;
use KFoobar\Fortnox\Resources\FinancialYear\FinancialYears;
use KFoobar\Fortnox\Resources\Supplier\SupplierInvoiceFileConnections;

class Fortnox
{

    protected Client $client;
    /**
     * Constructs a new instance.
     */
    public function __construct()
    {
        //$this->client = new Client;
    }

    public function forCompany(mixed $company): Fortnox
    {
        $clone = clone $this;
        $clone->client = new Client($company['client_id'], $company['client_secret'], $company['code'] ?? null, $company['redirect_uri'] ?? null);
        return $clone;
    }

    /**
     * Returns the accounts resource.
     *
     * @return \KFoobar\Fortnox\Resources\Account\Accounts
     */
    public function accounts()
    {
        return new Accounts($this->client);
    }

    /**
     * Returns the cost centers resource.
     *
     * @return \KFoobar\Fortnox\Resources\CostCenter\CostCenters
     */
    public function costCenters()
    {
        return new CostCenters($this->client);
    }

    /**
     * Returns the currencies resource.
     *
     * @return \KFoobar\Fortnox\Resources\Currency\Currencies
     */
    public function currencies()
    {
        return new Currencies($this->client);
    }

    /**
     * Returns the customers resource.
     *
     * @return \KFoobar\Fortnox\Resources\Customer\Customers
     */
    public function customers()
    {
        return new Customers($this->client);
    }

    /**
     * Returns the financial years resource.
     *
     * @return \KFoobar\Fortnox\Resources\FinancialYear\FinancialYears
     */
    public function financialYears()
    {
        return new FinancialYears($this->client);
    }

    /**
     * Returns the inbox resource.
     *
     * @return \KFoobar\Fortnox\Resources\Invoice\Invoices
     */
    public function inboxes()
    {
        return new Inboxes($this->client);
    }

    /**
     * Returns the invoices resource.
     *
     * @return \KFoobar\Fortnox\Resources\Invoice\Invoices
     */
    public function invoices()
    {
        return new Invoices($this->client);
    }

    /**
     * Returns the invoices accruals resource.
     *
     * @return \KFoobar\Fortnox\Resources\Invoice\InvoiceAccruals
     */
    public function invoiceAccruals()
    {
        return new InvoiceAccruals($this->client);
    }

    /**
     * Returns the invoices payments resource.
     *
     * @return \KFoobar\Fortnox\Resources\Invoice\InvoicePayments
     */
    public function invoicePayments()
    {
        return new InvoicePayments($this->client);
    }

    /**
     * Returns the price lists resource.
     *
     * @return \KFoobar\Fortnox\Resources\Price\PriceLists
     */
    public function priceLists()
    {
        return new PriceLists($this->client);
    }

    /**
     * Returns the projects resource.
     *
     * @return \KFoobar\Fortnox\Resources\Account\Projects
     */
    public function projects()
    {
        return new Projects($this->client);
    }

    /**
     * Returns the supplier invoices resource.
     *
     * @return \KFoobar\Fortnox\Resources\Supplier\SupplierInvoices
     */
    public function supplierInvoices()
    {
        return new SupplierInvoices($this->client);
    }

    /**
     * Returns the supplier invoices resource.
     *
     * @return \KFoobar\Fortnox\Resources\Supplier\SupplierInvoices
     */
    public function supplierInvoiceFileConnections()
    {
        return new SupplierInvoiceFileConnections($this->client);
    }

    /**
     * Returns the suppliers resource.
     *
     * @return \KFoobar\Fortnox\Resources\Supplier\Suppliers
     */
    public function suppliers()
    {
        return new Suppliers($this->client);
    }

    /**
     * Returns the print templates resource.
     *
     * @return \KFoobar\Fortnox\Resources\Template\PrintTemplates
     */
    public function printTemplates()
    {
        return new PrintTemplates($this->client);
    }

    /**
     * Returns the terms of deliveries resource.
     *
     * @return \KFoobar\Fortnox\Resources\Terms\TermsOfDeliveries
     */
    public function termsOfDeliveries()
    {
        return new TermsOfDeliveries($this->client);
    }

    /**
     * Returns the terms of payments resource.
     *
     * @return \KFoobar\Fortnox\Resources\Terms\TermsOfPayments
     */
    public function termsOfPayments()
    {
        return new TermsOfPayments($this->client);
    }

    /**
     * Returns the units resource.
     *
     * @return \KFoobar\Fortnox\Resources\Unit\Units
     */
    public function units()
    {
        return new Units($this->client);
    }

    /**
     * Returns the vouchers resource.
     *
     * @return \KFoobar\Fortnox\Resources\Voucher\Vouchers
     */
    public function vouchers()
    {
        return new Vouchers($this->client);
    }

    /**
     * Returns the voucher series resource.
     *
     * @return \KFoobar\Fortnox\Resources\Voucher\VoucherSeries
     */
    public function voucherSeries()
    {
        return new VoucherSeries($this->client);
    }
}
