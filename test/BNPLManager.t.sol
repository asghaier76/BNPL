// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {console2} from "forge-std/console2.sol";

import {BNPLManager} from "../src/BNPLManager.sol";
import {AllowanceAuth} from "../src/strategies/AllowanceAuth.sol";
import {PermitAuth} from "../src/strategies/PermitAuth.sol";
import {MerkleScheduleAuth} from "../src/strategies/MerkleScheduleAuth.sol";
import {EIP3009Auth} from "../src/strategies/EIP3009Auth.sol";
import {IPaymentAuth} from "../src/interfaces/IPaymentAuth.sol";
import {IBNPL} from "../src/interfaces/IBNPL.sol";

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {ERC20Permit} from "@openzeppelin/contracts/token/ERC20/extensions/ERC20Permit.sol";
import {MerkleProof} from "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";

// ============ Test tokens ============

/// @dev Standard ERC-20 token (no permit, no bool return issue)
contract MockERC20 is ERC20 {
    constructor() ERC20("Mock Token", "MKT") {}
    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}

/// @dev ERC-2612 permit-enabled token
contract MockERC20Permit is ERC20Permit {
    constructor() ERC20("Permit Token", "PKT") ERC20Permit("Permit Token") {}
    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}

/// @dev Simulates USDT-style token that does NOT return bool from transferFrom
contract MockNonBoolERC20 is ERC20 {
    constructor() ERC20("NonBool Token", "NBT") {}
    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
    // Override transferFrom to return nothing (USDT behavior)
    function transferFrom(address from, address to, uint256 amount)
        public override returns (bool)
    {
        // Call parent but swallow return — simulate no-return-value token
        super.transferFrom(from, to, amount);
        assembly { return(0, 0) } // return nothing
    }
}

/// @dev Mock EIP-3009 token (simulates USDC v2+)
contract MockEIP3009Token is ERC20 {
    // EIP-712 domain separator components
    bytes32 private constant EIP712_DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );
    bytes32 private constant RECEIVE_WITH_AUTHORIZATION_TYPEHASH = keccak256(
        "ReceiveWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)"
    );

    bytes32 public DOMAIN_SEPARATOR;

    // Tracks used authorization nonces: authorizer => nonce => used
    mapping(address => mapping(bytes32 => bool)) private _authorizationStates;

    constructor() ERC20("Mock USDC", "USDC") {
        DOMAIN_SEPARATOR = keccak256(abi.encode(
            EIP712_DOMAIN_TYPEHASH,
            keccak256(bytes("Mock USDC")),
            keccak256(bytes("2")),
            block.chainid,
            address(this)
        ));
    }

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }

    /// @notice Check if an authorization nonce has been used
    function authorizationState(address authorizer, bytes32 nonce)
        external view returns (bool)
    {
        return _authorizationStates[authorizer][nonce];
    }

    /// @notice Execute a transfer with a signed authorization (EIP-3009)
    /// @dev Requires msg.sender == to for front-running protection
    function receiveWithAuthorization(
        address from,
        address to,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce,
        bytes calldata signature
    ) external {
        require(msg.sender == to, "EIP3009: caller must be the payee");
        require(block.timestamp > validAfter, "EIP3009: authorization not yet valid");
        require(block.timestamp < validBefore, "EIP3009: authorization expired");
        require(!_authorizationStates[from][nonce], "EIP3009: authorization already used");

        // Verify signature
        bytes32 structHash = keccak256(abi.encode(
            RECEIVE_WITH_AUTHORIZATION_TYPEHASH,
            from,
            to,
            value,
            validAfter,
            validBefore,
            nonce
        ));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash));

        address recovered = _recoverSigner(digest, signature);
        require(recovered == from, "EIP3009: invalid signature");

        // Mark nonce as used
        _authorizationStates[from][nonce] = true;

        // Execute transfer
        _transfer(from, to, value);
    }

    function _recoverSigner(bytes32 digest, bytes calldata sig)
        internal pure returns (address)
    {
        require(sig.length == 65, "EIP3009: invalid signature length");
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := calldataload(sig.offset)
            s := calldataload(add(sig.offset, 32))
            v := byte(0, calldataload(add(sig.offset, 64)))
        }
        return ecrecover(digest, v, r, s);
    }
}

// ============ EIP-1271 mock wallet ============

contract MockSmartWallet {
    address public owner;
    constructor(address _owner) { owner = _owner; }

    function isValidSignature(bytes32 hash, bytes calldata sig)
        external view returns (bytes4)
    {
        // Recover and compare
        (address recovered,,) = _recover(hash, sig);
        if (recovered == owner) return bytes4(0x1626ba7e);
        return bytes4(0);
    }

    function _recover(bytes32 hash, bytes calldata sig)
        internal pure returns (address, bytes32, bytes32)
    {
        require(sig.length == 65, "bad sig length");
        bytes32 r; bytes32 s; uint8 v;
        assembly {
            r := calldataload(sig.offset)
            s := calldataload(add(sig.offset, 32))
            v := byte(0, calldataload(add(sig.offset, 64)))
        }
        return (ecrecover(hash, v, r, s), r, s);
    }
}

// ============ Base test setup ============

contract BNPLTestBase is Test {

    BNPLManager      public manager;
    AllowanceAuth    public allowanceAuth;
    PermitAuth       public permitAuth;
    MerkleScheduleAuth public merkleAuth;
    EIP3009Auth      public eip3009Auth;

    MockERC20        public token;
    MockERC20Permit  public permitToken;
    MockNonBoolERC20 public nonBoolToken;
    MockEIP3009Token public eip3009Token;

    address public merchant  = makeAddr("merchant");
    address public customer  = makeAddr("customer");
    address public operator  = makeAddr("operator");
    address public stranger  = makeAddr("stranger");

    uint256 public customerPk;

    // Standard order parameters
    uint256 constant TOTAL_AMOUNT      = 1000e18;   // 1000 tokens
    uint8   constant INSTALLMENTS      = 4;
    uint256 constant DOWN_PAYMENT_BPS  = 2500;       // 25%
    uint256 constant INSTALLMENT_PERIOD = 30 days;
    uint256 constant GRACE_PERIOD      = 3 days;
    uint256 constant LATE_FEE_BPS      = 500;        // 5%

    function setUp() public virtual {
        // Deploy strategies
        allowanceAuth = new AllowanceAuth();
        permitAuth    = new PermitAuth();
        merkleAuth    = new MerkleScheduleAuth();
        eip3009Auth   = new EIP3009Auth();

        // Deploy manager
        manager = new BNPLManager();

        // Deploy tokens
        token        = new MockERC20();
        permitToken  = new MockERC20Permit();
        nonBoolToken = new MockNonBoolERC20();
        eip3009Token = new MockEIP3009Token();

        // Give customer a funded EOA private key for signing
        customerPk = 0xA11CE;
        customer   = vm.addr(customerPk);

        // Fund customer
        token.mint(customer, TOTAL_AMOUNT * 10);
        permitToken.mint(customer, TOTAL_AMOUNT * 10);
        nonBoolToken.mint(customer, TOTAL_AMOUNT * 10);
        eip3009Token.mint(customer, TOTAL_AMOUNT * 10);
    }

    // ============ EIP-712 helpers ============

    function _domainSeparator() internal view returns (bytes32) {
        return keccak256(abi.encode(
            keccak256(
                "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
            ),
            keccak256(bytes("BNPL")),
            keccak256(bytes("1")),
            block.chainid,
            address(manager)
        ));
    }

    function _signOrderAuthorization(
        uint256 signerPk,
        address _merchant,
        address _token,
        uint256 _totalAmount,
        uint8   _installments,
        uint256 _downPaymentBps,
        uint256 _installmentPeriod,
        uint256 _gracePeriod,
        uint256 _lateFeeBps,
        address _downAuth,
        address _installAuth,
        uint256 _nonce,
        uint256 _deadline
    ) internal view returns (bytes memory sig) {
        bytes32 structHash = keccak256(abi.encode(
            keccak256(
                "OrderAuthorization(address merchant,address token,uint256 totalAmount,"
                "uint8 installments,uint256 downPaymentBps,uint256 installmentPeriod,"
                "uint256 gracePeriod,uint256 lateFeeBps,address downPaymentAuthStrategy,"
                "address installmentAuthStrategy,uint256 nonce,uint256 deadline)"
            ),
            _merchant, _token, _totalAmount, _installments, _downPaymentBps,
            _installmentPeriod, _gracePeriod, _lateFeeBps,
            _downAuth, _installAuth, _nonce, _deadline
        ));
        bytes32 digest = keccak256(abi.encodePacked(
            "\x19\x01",
            _domainSeparator(),
            structHash
        ));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPk, digest);
        return abi.encodePacked(r, s, v);
    }

    function _defaultSig(
        address _downAuth,
        address _installAuth,
        address _token
    ) internal view returns (bytes memory) {
        return _signOrderAuthorization(
            customerPk, merchant, _token, TOTAL_AMOUNT, INSTALLMENTS,
            DOWN_PAYMENT_BPS, INSTALLMENT_PERIOD, GRACE_PERIOD, LATE_FEE_BPS,
            _downAuth, _installAuth,
            manager.authorizationNonce(customer),
            block.timestamp + 1 hours
        );
    }

    function _precomputeOrderId(
        address _customer,
        address _merchant,
        address _token,
        uint256 _totalAmount,
        uint8   _installments,
        uint256 _downPaymentBps,
        uint256 _installmentPeriod
    ) internal view returns (bytes32) {
        return keccak256(abi.encode(
            _customer, _merchant, _token, _totalAmount,
            _installments, _downPaymentBps, _installmentPeriod,
            block.timestamp,
            manager.authorizationNonce(_customer)
        ));
    }
}

// ============================================================
// Test Suite 1 — Strategy: AllowanceAuth + AllowanceAuth
// ============================================================

contract TestAllowanceAllowance is BNPLTestBase {

    bytes32 orderId;
    uint256 deadline;
    bytes   originalSig; // Store the original sig for replay test

    function setUp() public override {
        super.setUp();
        deadline = block.timestamp + 1 hours;

        // Customer approves AllowanceAuth strategy (it calls transferFrom)
        vm.prank(customer);
        token.approve(address(allowanceAuth), type(uint256).max);

        originalSig = _defaultSig(
            address(allowanceAuth),
            address(allowanceAuth),
            address(token)
        );

        vm.prank(merchant);
        orderId = manager.createOrder(
            customer,
            address(token),
            TOTAL_AMOUNT,
            INSTALLMENTS,
            DOWN_PAYMENT_BPS,
            INSTALLMENT_PERIOD,
            GRACE_PERIOD,
            LATE_FEE_BPS,
            address(allowanceAuth),
            address(allowanceAuth),
            deadline,
            originalSig,
            ""   // AllowanceAuth needs no authData
        );
    }

    function test_createOrder_downPaymentCollected() public view {
        uint256 expectedDown = TOTAL_AMOUNT * DOWN_PAYMENT_BPS / 10000;
        IBNPL.Order memory o = manager.getOrder(orderId);
        assertEq(o.paidAmount, expectedDown,        "paidAmount wrong");
        assertEq(o.paidInstallments, 0,             "paidInstallments wrong");
        assertEq(uint8(o.status), uint8(IBNPL.OrderStatus.Active), "status wrong");
        assertEq(
            token.balanceOf(merchant),
            expectedDown,
            "merchant balance wrong after down payment"
        );
    }

    function test_collectInstallment_onTime() public {
        vm.warp(block.timestamp + INSTALLMENT_PERIOD);

        uint256 merchantBefore = token.balanceOf(merchant);
        vm.prank(merchant);
        manager.collectInstallment(orderId, "");

        IBNPL.Order memory o = manager.getOrder(orderId);
        assertEq(o.paidInstallments, 1, "paidInstallments wrong");

        // No late fee — on time
        uint256 expectedInstallment = _expectedInstallmentAmt(0);
        assertEq(
            token.balanceOf(merchant) - merchantBefore,
            expectedInstallment,
            "collected amount wrong"
        );
    }

    function test_collectInstallment_withLateFee() public {
        // Warp past due date but within grace
        vm.warp(block.timestamp + INSTALLMENT_PERIOD + 1 days);

        (uint256 principal, uint256 lateFee) = manager.getNextInstallment(orderId);
        assertGt(lateFee, 0, "late fee should be non-zero");

        uint256 merchantBefore = token.balanceOf(merchant);
        vm.prank(merchant);
        manager.collectInstallment(orderId, "");

        assertEq(
            token.balanceOf(merchant) - merchantBefore,
            principal + lateFee,
            "collected amount with late fee wrong"
        );
    }

    function test_collectAllInstallments_orderCompletes() public {
        uint256 startTime = block.timestamp;
        for (uint8 i = 0; i < INSTALLMENTS; i++) {
            vm.warp(startTime + INSTALLMENT_PERIOD * (i + 1));
            vm.prank(merchant);
            manager.collectInstallment(orderId, "");
        }
        IBNPL.Order memory o = manager.getOrder(orderId);
        assertEq(uint8(o.status), uint8(IBNPL.OrderStatus.Completed), "should be completed");
    }

    function test_getSchedule_returnsCorrectAmounts() public view {
        (uint256[] memory amounts, uint256[] memory dueDates) =
            manager.getSchedule(orderId);

        assertEq(amounts.length, INSTALLMENTS,  "wrong schedule length");
        assertEq(dueDates.length, INSTALLMENTS, "wrong dueDates length");

        // Verify sum of installments + down payment == totalAmount
        uint256 downPayment = TOTAL_AMOUNT * DOWN_PAYMENT_BPS / 10000;
        uint256 total = downPayment;
        for (uint256 i = 0; i < amounts.length; i++) {
            total += amounts[i];
        }
        assertEq(total, TOTAL_AMOUNT, "schedule amounts don't sum to totalAmount");
    }

    function test_getNextInstallment_matchesCollect() public {
        vm.warp(block.timestamp + INSTALLMENT_PERIOD);

        (uint256 principal,) = manager.getNextInstallment(orderId);
        uint256 merchantBefore = token.balanceOf(merchant);
        vm.prank(merchant);
        manager.collectInstallment(orderId, "");

        // Principal collected should match what getNextInstallment returned
        // (no late fee since we're exactly at due time)
        assertEq(
            token.balanceOf(merchant) - merchantBefore,
            principal,
            "collected amount doesn't match getNextInstallment"
        );
    }

    function test_operator_canCollect() public {
        vm.warp(block.timestamp + INSTALLMENT_PERIOD);

        vm.prank(merchant);
        manager.authorizeOperator(operator);

        vm.prank(operator);
        manager.collectInstallment(orderId, "");

        IBNPL.Order memory o = manager.getOrder(orderId);
        assertEq(o.paidInstallments, 1, "operator collection failed");
    }

    function test_stranger_cannotCollect() public {
        vm.warp(block.timestamp + INSTALLMENT_PERIOD);

        vm.prank(stranger);
        vm.expectRevert("BNPL: caller not authorized");
        manager.collectInstallment(orderId, "");
    }

    function test_collectTooEarly_reverts() public {
        vm.prank(merchant);
        vm.expectRevert("BNPL: payment not yet due");
        manager.collectInstallment(orderId, "");
    }

    function test_payOffEarly() public {
        vm.prank(customer);
        manager.payOffEarly(orderId, "");

        IBNPL.Order memory o = manager.getOrder(orderId);
        assertEq(uint8(o.status), uint8(IBNPL.OrderStatus.Completed), "should be completed");
        assertEq(o.paidAmount, TOTAL_AMOUNT, "paidAmount should equal totalAmount");
    }

    function test_markDefaulted_afterGrace() public {
        vm.warp(block.timestamp + INSTALLMENT_PERIOD + GRACE_PERIOD + 1);

        vm.prank(merchant);
        manager.markDefaulted(orderId);

        IBNPL.Order memory o = manager.getOrder(orderId);
        assertEq(uint8(o.status), uint8(IBNPL.OrderStatus.Defaulted), "should be defaulted");
    }

    function test_markDefaulted_beforeGrace_reverts() public {
        vm.warp(block.timestamp + INSTALLMENT_PERIOD + GRACE_PERIOD - 1);

        vm.prank(merchant);
        vm.expectRevert("BNPL: grace period not elapsed");
        manager.markDefaulted(orderId);
    }

    function test_stranger_cannotMarkDefaulted() public {
        vm.warp(block.timestamp + INSTALLMENT_PERIOD + GRACE_PERIOD + 1);

        vm.prank(stranger);
        vm.expectRevert("BNPL: only merchant or operator");
        manager.markDefaulted(orderId);
    }

    function test_customerCancel_refundsInstallments() public {
        // Collect one installment first
        vm.warp(block.timestamp + INSTALLMENT_PERIOD);
        vm.prank(merchant);
        manager.collectInstallment(orderId, "");

        // Merchant must approve refund transfer back to customer
        uint256 downPayment = TOTAL_AMOUNT * DOWN_PAYMENT_BPS / 10000;
        uint256 installmentAmt = _expectedInstallmentAmt(0);
        uint256 expectedRefund = installmentAmt; // down payment forfeit

        vm.prank(merchant);
        token.approve(address(manager), expectedRefund);

        uint256 customerBefore = token.balanceOf(customer);
        vm.prank(customer);
        manager.cancelOrder(orderId);

        assertApproxEqAbs(
            token.balanceOf(customer) - customerBefore,
            expectedRefund,
            1, // allow 1 wei dust
            "customer refund wrong"
        );
        // Silence unused variable warning
        assertGt(downPayment, 0);
    }

    function test_merchantCancel_fullRefund() public {
        uint256 downPayment = TOTAL_AMOUNT * DOWN_PAYMENT_BPS / 10000;

        // Merchant must approve the refund
        vm.prank(merchant);
        token.approve(address(manager), downPayment);

        uint256 customerBefore = token.balanceOf(customer);
        vm.prank(merchant);
        manager.cancelOrder(orderId);

        assertEq(
            token.balanceOf(customer) - customerBefore,
            downPayment,
            "merchant-initiated cancel should refund down payment"
        );
    }

    function test_dustInFinalInstallment() public {
        // Use a totalAmount that doesn't divide evenly
        // e.g. 1001e18 with 25% down = 750.75e18 remaining, / 4 = 187.6875...
        // In integer math: 750750000000000000000 / 4 = 187687500000000000000 rem 0
        // Let's use 1003e18: 25% down = 250.75e18, remaining = 752.25e18
        // Actually simpler: totalAmount=1003 (no decimals for clarity)
        MockERC20 tk = new MockERC20();
        uint256 amt = 1003; // 3 wei dust after 4 installments
        tk.mint(customer, amt * 10);

        vm.prank(customer);
        tk.approve(address(allowanceAuth), type(uint256).max);

        bytes memory sig = _signOrderAuthorization(
            customerPk, merchant, address(tk), amt, 4,
            DOWN_PAYMENT_BPS, INSTALLMENT_PERIOD, GRACE_PERIOD, LATE_FEE_BPS,
            address(allowanceAuth), address(allowanceAuth),
            manager.authorizationNonce(customer),
            block.timestamp + 1 hours
        );

        vm.prank(merchant);
        bytes32 oid = manager.createOrder(
            customer, address(tk), amt, 4, DOWN_PAYMENT_BPS,
            INSTALLMENT_PERIOD, GRACE_PERIOD, LATE_FEE_BPS,
            address(allowanceAuth), address(allowanceAuth),
            block.timestamp + 1 hours, sig, ""
        );

        // Collect all 4 installments
        uint256 startTime = block.timestamp;
        for (uint8 i = 0; i < 4; i++) {
            vm.warp(startTime + INSTALLMENT_PERIOD * (i + 1));
            vm.prank(merchant);
            manager.collectInstallment(oid, "");
        }

        IBNPL.Order memory o = manager.getOrder(oid);
        assertEq(uint8(o.status), uint8(IBNPL.OrderStatus.Completed), "should complete");
        assertEq(o.paidAmount, amt, "total paid should equal totalAmount");
    }

    function test_noncePreventsReplay() public {
        // After one successful createOrder the nonce has incremented
        // Trying to use the same sig again should fail since it was signed with nonce=0
        // but the current nonce is now 1
        vm.prank(merchant);
        vm.expectRevert("BNPL: invalid signature");
        manager.createOrder(
            customer, address(token), TOTAL_AMOUNT, INSTALLMENTS,
            DOWN_PAYMENT_BPS, INSTALLMENT_PERIOD, GRACE_PERIOD, LATE_FEE_BPS,
            address(allowanceAuth), address(allowanceAuth),
            deadline, originalSig, ""
        );
    }

    // ============ Helper ============
    function _expectedInstallmentAmt(uint8 idx) internal pure returns (uint256) {
        uint256 downPayment = TOTAL_AMOUNT * DOWN_PAYMENT_BPS / 10000;
        uint256 remaining   = TOTAL_AMOUNT - downPayment;
        uint256 base        = remaining / INSTALLMENTS;
        uint256 dust        = remaining % INSTALLMENTS;
        return (idx == INSTALLMENTS - 1) ? base + dust : base;
    }
}

// ============================================================
// Test Suite 2 — Strategy: PermitAuth (down) + AllowanceAuth (install)
// ============================================================

contract TestPermitAllowance is BNPLTestBase {

    bytes32 orderId;
    MockERC20Permit pToken;

    function setUp() public override {
        super.setUp();
        pToken = permitToken;

        // Customer approves AllowanceAuth for installments (it calls transferFrom)
        vm.prank(customer);
        pToken.approve(address(allowanceAuth), type(uint256).max);

        // Build permit signature for down payment
        uint256 downPayment = TOTAL_AMOUNT * DOWN_PAYMENT_BPS / 10000;
        uint256 permitDeadline = block.timestamp + 1 hours;

        (uint8 v, bytes32 r, bytes32 s) = _signPermit(
            customerPk,
            address(pToken),
            address(permitAuth),
            downPayment,
            0,  // nonce
            permitDeadline
        );
        bytes memory permitAuthData = abi.encode(permitDeadline, v, r, s);

        bytes memory orderSig = _signOrderAuthorization(
            customerPk, merchant, address(pToken), TOTAL_AMOUNT, INSTALLMENTS,
            DOWN_PAYMENT_BPS, INSTALLMENT_PERIOD, GRACE_PERIOD, LATE_FEE_BPS,
            address(permitAuth), address(allowanceAuth),
            manager.authorizationNonce(customer),
            permitDeadline
        );

        vm.prank(merchant);
        orderId = manager.createOrder(
            customer, address(pToken), TOTAL_AMOUNT, INSTALLMENTS,
            DOWN_PAYMENT_BPS, INSTALLMENT_PERIOD, GRACE_PERIOD, LATE_FEE_BPS,
            address(permitAuth),
            address(allowanceAuth),
            permitDeadline,
            orderSig,
            permitAuthData
        );
    }

    function test_downPayment_collectedViaPermit() public view {
        uint256 expectedDown = TOTAL_AMOUNT * DOWN_PAYMENT_BPS / 10000;
        IBNPL.Order memory o = manager.getOrder(orderId);
        assertEq(o.paidAmount, expectedDown, "down payment wrong");
        assertEq(pToken.balanceOf(merchant), expectedDown, "merchant balance wrong");
    }

    function test_installment_collectedViaAllowance() public {
        vm.warp(block.timestamp + INSTALLMENT_PERIOD);
        uint256 before = pToken.balanceOf(merchant);

        vm.prank(merchant);
        manager.collectInstallment(orderId, "");

        assertGt(pToken.balanceOf(merchant), before, "installment not collected");
    }

    // ============ Helper ============
    function _signPermit(
        uint256 pk,
        address _token,
        address spender,
        uint256 value,
        uint256 nonce,
        uint256 _deadline
    ) internal view returns (uint8 v, bytes32 r, bytes32 s) {
        bytes32 domSep = MockERC20Permit(_token).DOMAIN_SEPARATOR();
        bytes32 structHash = keccak256(abi.encode(
            keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)"),
            vm.addr(pk), spender, value, nonce, _deadline
        ));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domSep, structHash));
        (v, r, s) = vm.sign(pk, digest);
    }
}

// ============================================================
// Test Suite 3 — NonBoolERC20 token (USDT-style) with AllowanceAuth
// Validates SafeERC20 handles missing bool return value
// ============================================================

contract TestNonBoolToken is BNPLTestBase {

    bytes32 orderId;

    function setUp() public override {
        super.setUp();

        // Customer approves AllowanceAuth strategy (it calls transferFrom)
        vm.prank(customer);
        nonBoolToken.approve(address(allowanceAuth), type(uint256).max);

        bytes memory sig = _signOrderAuthorization(
            customerPk, merchant, address(nonBoolToken), TOTAL_AMOUNT, INSTALLMENTS,
            DOWN_PAYMENT_BPS, INSTALLMENT_PERIOD, GRACE_PERIOD, LATE_FEE_BPS,
            address(allowanceAuth), address(allowanceAuth),
            manager.authorizationNonce(customer),
            block.timestamp + 1 hours
        );

        vm.prank(merchant);
        orderId = manager.createOrder(
            customer, address(nonBoolToken), TOTAL_AMOUNT, INSTALLMENTS,
            DOWN_PAYMENT_BPS, INSTALLMENT_PERIOD, GRACE_PERIOD, LATE_FEE_BPS,
            address(allowanceAuth), address(allowanceAuth),
            block.timestamp + 1 hours, sig, ""
        );
    }

    function test_downPayment_nonBoolToken() public view {
        uint256 expectedDown = TOTAL_AMOUNT * DOWN_PAYMENT_BPS / 10000;
        IBNPL.Order memory o = manager.getOrder(orderId);
        assertEq(o.paidAmount, expectedDown, "down payment with non-bool token failed");
    }

    function test_installment_nonBoolToken() public {
        vm.warp(block.timestamp + INSTALLMENT_PERIOD);
        uint256 before = nonBoolToken.balanceOf(merchant);
        vm.prank(merchant);
        manager.collectInstallment(orderId, "");
        assertGt(nonBoolToken.balanceOf(merchant), before, "installment with non-bool token failed");
    }
}

// ============================================================
// Test Suite 4 — EIP-1271 Smart Contract Wallet
// ============================================================

contract TestSmartWalletCustomer is BNPLTestBase {

    bytes32 orderId;
    MockSmartWallet wallet;
    uint256 walletOwnerPk;
    address walletOwner;

    function setUp() public override {
        super.setUp();

        walletOwnerPk = 0xB0B;
        walletOwner   = vm.addr(walletOwnerPk);
        wallet        = new MockSmartWallet(walletOwner);

        // Fund the smart wallet
        token.mint(address(wallet), TOTAL_AMOUNT * 10);

        // Approve AllowanceAuth from the smart wallet (it calls transferFrom)
        vm.prank(address(wallet));
        token.approve(address(allowanceAuth), type(uint256).max);

        // Sign the OrderAuthorization with the wallet owner's key
        bytes memory sig = _signOrderAuthorization(
            walletOwnerPk, merchant, address(token), TOTAL_AMOUNT, INSTALLMENTS,
            DOWN_PAYMENT_BPS, INSTALLMENT_PERIOD, GRACE_PERIOD, LATE_FEE_BPS,
            address(allowanceAuth), address(allowanceAuth),
            manager.authorizationNonce(address(wallet)),
            block.timestamp + 1 hours
        );

        vm.prank(merchant);
        orderId = manager.createOrder(
            address(wallet),    // customer is the smart wallet
            address(token), TOTAL_AMOUNT, INSTALLMENTS,
            DOWN_PAYMENT_BPS, INSTALLMENT_PERIOD, GRACE_PERIOD, LATE_FEE_BPS,
            address(allowanceAuth), address(allowanceAuth),
            block.timestamp + 1 hours, sig, ""
        );
    }

    function test_smartWalletCustomer_orderCreated() public view {
        IBNPL.Order memory o = manager.getOrder(orderId);
        assertEq(o.customer, address(wallet), "customer should be smart wallet");
        uint256 expectedDown = TOTAL_AMOUNT * DOWN_PAYMENT_BPS / 10000;
        assertEq(o.paidAmount, expectedDown, "down payment wrong");
    }

    function test_smartWalletCustomer_collectInstallment() public {
        vm.warp(block.timestamp + INSTALLMENT_PERIOD);
        vm.prank(merchant);
        manager.collectInstallment(orderId, "");
        IBNPL.Order memory o = manager.getOrder(orderId);
        assertEq(o.paidInstallments, 1, "installment not collected");
    }
}

// ============================================================
// Test Suite 5 — MerkleScheduleAuth (variable installments)
// ============================================================

contract TestMerkleScheduleAuth is BNPLTestBase {

    MerkleScheduleAuth merkle;
    bytes32 orderId;

    // Variable schedule: 4 installments with different amounts
    uint256[] leafAmounts;
    uint256[] leafDueDates;
    bytes32[] leaves;
    bytes32   merkleRoot;

    function setUp() public override {
        super.setUp();
        merkle = merkleAuth;

        // Customer approves AllowanceAuth for down payment and MerkleScheduleAuth for installments
        // (both call safeTransferFrom as msg.sender)
        vm.prank(customer);
        token.approve(address(allowanceAuth), type(uint256).max);
        vm.prank(customer);
        token.approve(address(merkleAuth), type(uint256).max);

        // Build a 4-leaf variable schedule
        // totalAmount = 1000e18, downPayment = 25% = 250e18
        // remaining = 750e18 split non-uniformly: 100, 200, 200, 250
        uint256 t0 = block.timestamp;
        leafAmounts   = new uint256[](4);
        leafDueDates  = new uint256[](4);
        leaves        = new bytes32[](4);

        leafAmounts[0] = 100e18; leafDueDates[0] = t0 + 30 days;
        leafAmounts[1] = 200e18; leafDueDates[1] = t0 + 60 days;
        leafAmounts[2] = 200e18; leafDueDates[2] = t0 + 90 days;
        leafAmounts[3] = 250e18; leafDueDates[3] = t0 + 120 days;

        for (uint256 i = 0; i < 4; i++) {
            leaves[i] = keccak256(abi.encode(i, leafAmounts[i], leafDueDates[i]));
        }

        // Build merkle tree (sorted sibling hashing, OZ compatible)
        merkleRoot = _buildMerkleRoot(leaves);

        // Pre-compute orderId (must match BNPLManager's derivation)
        bytes32 predictedOrderId = keccak256(abi.encode(
            customer, merchant, address(token), TOTAL_AMOUNT, INSTALLMENTS,
            DOWN_PAYMENT_BPS, INSTALLMENT_PERIOD,
            block.timestamp,
            manager.authorizationNonce(customer)
        ));

        // Register schedule BEFORE createOrder (in same tx via multicall in prod,
        // here we do it sequentially since test timestamps don't advance)
        merkle.registerSchedule(
            predictedOrderId,
            merkleRoot,
            bytes("ipfs://QmTest123")
        );

        bytes memory sig = _signOrderAuthorization(
            customerPk, merchant, address(token), TOTAL_AMOUNT, INSTALLMENTS,
            DOWN_PAYMENT_BPS, INSTALLMENT_PERIOD, GRACE_PERIOD, LATE_FEE_BPS,
            address(allowanceAuth),  // down payment uses AllowanceAuth
            address(merkle),         // installments use MerkleScheduleAuth
            manager.authorizationNonce(customer),
            block.timestamp + 1 hours
        );

        vm.prank(merchant);
        orderId = manager.createOrder(
            customer, address(token), TOTAL_AMOUNT, INSTALLMENTS,
            DOWN_PAYMENT_BPS, INSTALLMENT_PERIOD, GRACE_PERIOD, LATE_FEE_BPS,
            address(allowanceAuth),
            address(merkle),
            block.timestamp + 1 hours,
            sig,
            ""   // AllowanceAuth down payment needs no authData
        );

        // Verify orderId matches prediction
        assertEq(orderId, predictedOrderId, "orderId mismatch");
    }

    function test_getSchedule_returnsEmpty_forMerkleOrders() public view {
        (uint256[] memory amounts, uint256[] memory dueDates) =
            manager.getSchedule(orderId);
        assertEq(amounts.length, 0,  "should return empty for merkle orders");
        assertEq(dueDates.length, 0, "should return empty for merkle orders");
    }

    function test_collectFirstInstallment_withProof() public {
        vm.warp(leafDueDates[0]);

        bytes32[] memory proof = _getProof(0);
        bytes memory authData = abi.encode(
            orderId, uint256(0), leafAmounts[0], leafDueDates[0], proof
        );

        uint256 before = token.balanceOf(merchant);
        vm.prank(merchant);
        manager.collectInstallment(orderId, authData);

        assertEq(
            token.balanceOf(merchant) - before,
            leafAmounts[0],
            "wrong installment amount"
        );
    }

    function test_collectAllInstallments_variableAmounts() public {
        for (uint256 i = 0; i < 4; i++) {
            vm.warp(leafDueDates[i]);
            bytes32[] memory proof = _getProof(i);
            bytes memory authData = abi.encode(
                orderId, i, leafAmounts[i], leafDueDates[i], proof
            );
            vm.prank(merchant);
            manager.collectInstallment(orderId, authData);
        }

        IBNPL.Order memory o = manager.getOrder(orderId);
        assertEq(uint8(o.status), uint8(IBNPL.OrderStatus.Completed), "should be completed");
    }

    function test_replayLeaf_reverts() public {
        vm.warp(leafDueDates[0]);
        bytes32[] memory proof = _getProof(0);
        bytes memory authData = abi.encode(
            orderId, uint256(0), leafAmounts[0], leafDueDates[0], proof
        );

        vm.prank(merchant);
        manager.collectInstallment(orderId, authData);

        // Warp to next due date so BNPLManager timing check passes
        vm.warp(leafDueDates[1]);

        // Try to replay the same leaf — strategy should reject
        vm.prank(merchant);
        vm.expectRevert("MerkleScheduleAuth: leaf already consumed");
        manager.collectInstallment(orderId, authData);
    }

    function test_invalidProof_reverts() public {
        vm.warp(leafDueDates[0]);

        // Use leaf 1's proof for leaf 0's data
        bytes32[] memory wrongProof = _getProof(1);
        bytes memory authData = abi.encode(
            orderId, uint256(0), leafAmounts[0], leafDueDates[0], wrongProof
        );

        vm.prank(merchant);
        vm.expectRevert("MerkleScheduleAuth: invalid proof");
        manager.collectInstallment(orderId, authData);
    }

    function test_collectBeforeDueDate_reverts() public {
        // Do not warp — we're before leafDueDates[0]
        // BNPLManager checks timing before calling the strategy
        bytes32[] memory proof = _getProof(0);
        bytes memory authData = abi.encode(
            orderId, uint256(0), leafAmounts[0], leafDueDates[0], proof
        );

        vm.prank(merchant);
        vm.expectRevert("BNPL: payment not yet due");
        manager.collectInstallment(orderId, authData);
    }

    function test_registerScheduleTwice_reverts() public {
        vm.expectRevert("MerkleScheduleAuth: schedule already registered");
        merkle.registerSchedule(orderId, merkleRoot, bytes("ipfs://QmOther"));
    }

    function test_verifyInstallment_view() public view {
        bytes32[] memory proof = _getProof(0);
        bool valid = merkle.verifyInstallment(
            orderId, 0, leafAmounts[0], leafDueDates[0], proof
        );
        assertTrue(valid, "proof should be valid");
    }

    function test_testVectors() public pure {
        // Test vectors from ERC spec — 2-leaf schedule
        // Index 0: amount=500000, dueDate=1740000000
        // Index 1: amount=750000, dueDate=1742592000
        bytes32 l0 = keccak256(abi.encode(uint256(0), uint256(500000), uint256(1740000000)));
        bytes32 l1 = keccak256(abi.encode(uint256(1), uint256(750000), uint256(1742592000)));
        bytes32 root;
        if (l0 < l1) {
            root = keccak256(abi.encode(l0, l1));
        } else {
            root = keccak256(abi.encode(l1, l0));
        }
        // Root must be non-zero and deterministic
        assertNotEq(root, bytes32(0), "test vector root should be non-zero");
        // Verify proof for l0
        bytes32[] memory proof = new bytes32[](1);
        proof[0] = l1;
        bool valid = MerkleProof.verify(proof, root, l0);
        assertTrue(valid, "test vector proof for leaf 0 should be valid");
    }

    // ============ Merkle tree helpers ============

    function _buildMerkleRoot(bytes32[] memory _leaves)
        internal pure returns (bytes32)
    {
        // Simple 4-leaf tree: level0=[L0,L1,L2,L3], level1=[H01,H23], root=H0123
        require(_leaves.length == 4, "only 4-leaf tree supported in test");
        bytes32 h01 = _hashPair(_leaves[0], _leaves[1]);
        bytes32 h23 = _hashPair(_leaves[2], _leaves[3]);
        return _hashPair(h01, h23);
    }

    function _hashPair(bytes32 a, bytes32 b) internal pure returns (bytes32) {
        return a < b
            ? keccak256(abi.encode(a, b))
            : keccak256(abi.encode(b, a));
    }

    function _getProof(uint256 leafIndex)
        internal view returns (bytes32[] memory proof)
    {
        // For a 4-leaf tree, proof length is 2
        proof = new bytes32[](2);
        bytes32 h01 = _hashPair(leaves[0], leaves[1]);
        bytes32 h23 = _hashPair(leaves[2], leaves[3]);

        if (leafIndex == 0) {
            proof[0] = leaves[1];
            proof[1] = h23;
        } else if (leafIndex == 1) {
            proof[0] = leaves[0];
            proof[1] = h23;
        } else if (leafIndex == 2) {
            proof[0] = leaves[3];
            proof[1] = h01;
        } else {
            proof[0] = leaves[2];
            proof[1] = h01;
        }
    }
}

// ============================================================
// Test Suite 6 — Parameter validation & edge cases
// ============================================================

contract TestParameterValidation is BNPLTestBase {

    function setUp() public override {
        super.setUp();
        // Pre-approve AllowanceAuth so vm.expectRevert can target createOrder
        vm.prank(customer);
        token.approve(address(allowanceAuth), type(uint256).max);
    }

    function _makeSig(
        uint8 _installments,
        uint256 _downBps,
        uint256 _lateBps,
        uint256 _grace
    ) internal view returns (bytes memory) {
        return _signOrderAuthorization(
            customerPk, merchant, address(token), TOTAL_AMOUNT, _installments,
            _downBps, INSTALLMENT_PERIOD, _grace, _lateBps,
            address(allowanceAuth), address(allowanceAuth),
            manager.authorizationNonce(customer),
            block.timestamp + 1 hours
        );
    }

    function _create(
        uint8 _installments,
        uint256 _downBps,
        uint256 _lateBps,
        uint256 _grace,
        bytes memory _sig
    ) internal {
        vm.prank(merchant);
        manager.createOrder(
            customer, address(token), TOTAL_AMOUNT, _installments,
            _downBps, INSTALLMENT_PERIOD, _grace, _lateBps,
            address(allowanceAuth), address(allowanceAuth),
            block.timestamp + 1 hours, _sig, ""
        );
    }

    function test_installmentsTooLow_reverts() public {
        bytes memory sig = _makeSig(1, DOWN_PAYMENT_BPS, LATE_FEE_BPS, GRACE_PERIOD);
        vm.expectRevert("BNPL: installments out of range [2,12]");
        _create(1, DOWN_PAYMENT_BPS, LATE_FEE_BPS, GRACE_PERIOD, sig);
    }

    function test_installmentsTooHigh_reverts() public {
        bytes memory sig = _makeSig(13, DOWN_PAYMENT_BPS, LATE_FEE_BPS, GRACE_PERIOD);
        vm.expectRevert("BNPL: installments out of range [2,12]");
        _create(13, DOWN_PAYMENT_BPS, LATE_FEE_BPS, GRACE_PERIOD, sig);
    }

    function test_downPaymentTooLow_reverts() public {
        bytes memory sig = _makeSig(INSTALLMENTS, 999, LATE_FEE_BPS, GRACE_PERIOD);
        vm.expectRevert("BNPL: downPaymentBps out of range [1000,5000]");
        _create(INSTALLMENTS, 999, LATE_FEE_BPS, GRACE_PERIOD, sig);
    }

    function test_downPaymentTooHigh_reverts() public {
        bytes memory sig = _makeSig(INSTALLMENTS, 5001, LATE_FEE_BPS, GRACE_PERIOD);
        vm.expectRevert("BNPL: downPaymentBps out of range [1000,5000]");
        _create(INSTALLMENTS, 5001, LATE_FEE_BPS, GRACE_PERIOD, sig);
    }

    function test_lateFeeTooHigh_reverts() public {
        bytes memory sig = _makeSig(INSTALLMENTS, DOWN_PAYMENT_BPS, 1501, GRACE_PERIOD);
        vm.expectRevert("BNPL: lateFeeBps exceeds max 1500");
        _create(INSTALLMENTS, DOWN_PAYMENT_BPS, 1501, GRACE_PERIOD, sig);
    }

    function test_gracePeriodTooLong_reverts() public {
        uint256 tooLong = 2592001;
        bytes memory sig = _makeSig(INSTALLMENTS, DOWN_PAYMENT_BPS, LATE_FEE_BPS, tooLong);
        vm.expectRevert("BNPL: gracePeriod exceeds max 30 days");
        _create(INSTALLMENTS, DOWN_PAYMENT_BPS, LATE_FEE_BPS, tooLong, sig);
    }

    function test_expiredDeadline_reverts() public {
        vm.warp(block.timestamp + 2 hours);
        bytes memory sig = _signOrderAuthorization(
            customerPk, merchant, address(token), TOTAL_AMOUNT, INSTALLMENTS,
            DOWN_PAYMENT_BPS, INSTALLMENT_PERIOD, GRACE_PERIOD, LATE_FEE_BPS,
            address(allowanceAuth), address(allowanceAuth),
            manager.authorizationNonce(customer),
            block.timestamp - 1   // already expired
        );

        vm.prank(merchant);
        vm.expectRevert("BNPL: authorization expired");
        manager.createOrder(
            customer, address(token), TOTAL_AMOUNT, INSTALLMENTS,
            DOWN_PAYMENT_BPS, INSTALLMENT_PERIOD, GRACE_PERIOD, LATE_FEE_BPS,
            address(allowanceAuth), address(allowanceAuth),
            block.timestamp - 1,
            sig, ""
        );
    }

    function test_invalidStrategy_reverts() public {
        bytes memory sig = _signOrderAuthorization(
            customerPk, merchant, address(token), TOTAL_AMOUNT, INSTALLMENTS,
            DOWN_PAYMENT_BPS, INSTALLMENT_PERIOD, GRACE_PERIOD, LATE_FEE_BPS,
            address(0xDEAD), address(allowanceAuth),
            manager.authorizationNonce(customer),
            block.timestamp + 1 hours
        );

        vm.prank(merchant);
        vm.expectRevert("BNPL: downPaymentAuthStrategy does not implement IPaymentAuth");
        manager.createOrder(
            customer, address(token), TOTAL_AMOUNT, INSTALLMENTS,
            DOWN_PAYMENT_BPS, INSTALLMENT_PERIOD, GRACE_PERIOD, LATE_FEE_BPS,
            address(0xDEAD), address(allowanceAuth),
            block.timestamp + 1 hours, sig, ""
        );
    }
}

// ============================================================
// Test Suite 7 — Strategy: EIP3009Auth (down) + AllowanceAuth (install)
// EIP-3009 receiveWithAuthorization for USDC-style tokens
// ============================================================

contract TestEIP3009Auth is BNPLTestBase {

    bytes32 orderId;

    // EIP-712 constants for ReceiveWithAuthorization
    bytes32 private constant RECEIVE_WITH_AUTHORIZATION_TYPEHASH = keccak256(
        "ReceiveWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)"
    );

    function setUp() public override {
        super.setUp();

        // Customer approves AllowanceAuth for installments
        vm.prank(customer);
        eip3009Token.approve(address(allowanceAuth), type(uint256).max);
    }

    // ============ EIP-3009 signature helper ============

    function _signReceiveWithAuthorization(
        uint256 signerPk,
        address from,
        address to,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce
    ) internal view returns (bytes memory sig) {
        bytes32 structHash = keccak256(abi.encode(
            RECEIVE_WITH_AUTHORIZATION_TYPEHASH,
            from,
            to,
            value,
            validAfter,
            validBefore,
            nonce
        ));
        bytes32 digest = keccak256(abi.encodePacked(
            "\x19\x01",
            eip3009Token.DOMAIN_SEPARATOR(),
            structHash
        ));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPk, digest);
        return abi.encodePacked(r, s, v);
    }

    function _createOrderWithEIP3009() internal returns (bytes32) {
        uint256 downPayment = TOTAL_AMOUNT * DOWN_PAYMENT_BPS / 10000;
        uint256 validAfter = 0;
        uint256 validBefore = block.timestamp + 1 hours;
        bytes32 nonce = keccak256(abi.encode(customer, block.timestamp, "down"));

        // Sign the EIP-3009 authorization for the down payment
        // `to` must be the eip3009Auth contract address
        bytes memory eip3009Sig = _signReceiveWithAuthorization(
            customerPk,
            customer,           // from
            address(eip3009Auth), // to = strategy contract
            downPayment,
            validAfter,
            validBefore,
            nonce
        );

        // Encode authData for EIP3009Auth
        bytes memory downPaymentAuthData = abi.encode(
            validAfter,
            validBefore,
            nonce,
            eip3009Sig
        );

        // Sign the BNPL OrderAuthorization
        bytes memory orderSig = _signOrderAuthorization(
            customerPk, merchant, address(eip3009Token), TOTAL_AMOUNT, INSTALLMENTS,
            DOWN_PAYMENT_BPS, INSTALLMENT_PERIOD, GRACE_PERIOD, LATE_FEE_BPS,
            address(eip3009Auth), address(allowanceAuth),
            manager.authorizationNonce(customer),
            validBefore
        );

        vm.prank(merchant);
        return manager.createOrder(
            customer, address(eip3009Token), TOTAL_AMOUNT, INSTALLMENTS,
            DOWN_PAYMENT_BPS, INSTALLMENT_PERIOD, GRACE_PERIOD, LATE_FEE_BPS,
            address(eip3009Auth),
            address(allowanceAuth),
            validBefore,
            orderSig,
            downPaymentAuthData
        );
    }

    function test_downPayment_collectedViaEIP3009() public {
        uint256 merchantBefore = eip3009Token.balanceOf(merchant);
        uint256 customerBefore = eip3009Token.balanceOf(customer);
        uint256 expectedDown = TOTAL_AMOUNT * DOWN_PAYMENT_BPS / 10000;

        orderId = _createOrderWithEIP3009();

        IBNPL.Order memory o = manager.getOrder(orderId);
        assertEq(o.paidAmount, expectedDown, "paidAmount wrong");
        assertEq(
            eip3009Token.balanceOf(merchant) - merchantBefore,
            expectedDown,
            "merchant balance wrong"
        );
        assertEq(
            customerBefore - eip3009Token.balanceOf(customer),
            expectedDown,
            "customer balance wrong"
        );
    }

    function test_installment_collectedViaAllowance() public {
        orderId = _createOrderWithEIP3009();

        vm.warp(block.timestamp + INSTALLMENT_PERIOD);

        uint256 merchantBefore = eip3009Token.balanceOf(merchant);
        vm.prank(merchant);
        manager.collectInstallment(orderId, "");

        assertGt(
            eip3009Token.balanceOf(merchant),
            merchantBefore,
            "installment not collected"
        );

        IBNPL.Order memory o = manager.getOrder(orderId);
        assertEq(o.paidInstallments, 1, "paidInstallments wrong");
    }

    function test_nonceConsumed_afterDownPayment() public {
        uint256 downPayment = TOTAL_AMOUNT * DOWN_PAYMENT_BPS / 10000;
        bytes32 nonce = keccak256(abi.encode(customer, block.timestamp, "down"));

        // Nonce should not be used yet
        assertFalse(
            eip3009Auth.isNonceUsed(address(eip3009Token), customer, nonce),
            "nonce should not be used before order"
        );

        // Create order (consumes the nonce)
        uint256 validAfter = 0;
        uint256 validBefore = block.timestamp + 1 hours;

        bytes memory eip3009Sig = _signReceiveWithAuthorization(
            customerPk, customer, address(eip3009Auth), downPayment,
            validAfter, validBefore, nonce
        );

        bytes memory downPaymentAuthData = abi.encode(
            validAfter, validBefore, nonce, eip3009Sig
        );

        bytes memory orderSig = _signOrderAuthorization(
            customerPk, merchant, address(eip3009Token), TOTAL_AMOUNT, INSTALLMENTS,
            DOWN_PAYMENT_BPS, INSTALLMENT_PERIOD, GRACE_PERIOD, LATE_FEE_BPS,
            address(eip3009Auth), address(allowanceAuth),
            manager.authorizationNonce(customer), validBefore
        );

        vm.prank(merchant);
        manager.createOrder(
            customer, address(eip3009Token), TOTAL_AMOUNT, INSTALLMENTS,
            DOWN_PAYMENT_BPS, INSTALLMENT_PERIOD, GRACE_PERIOD, LATE_FEE_BPS,
            address(eip3009Auth), address(allowanceAuth),
            validBefore, orderSig, downPaymentAuthData
        );

        // Nonce should now be used
        assertTrue(
            eip3009Auth.isNonceUsed(address(eip3009Token), customer, nonce),
            "nonce should be used after order"
        );
    }

    function test_expiredAuthorization_reverts() public {
        uint256 downPayment = TOTAL_AMOUNT * DOWN_PAYMENT_BPS / 10000;
        uint256 validAfter = 0;
        uint256 validBefore = block.timestamp + 1 hours;
        bytes32 nonce = keccak256(abi.encode(customer, block.timestamp, "expired"));

        bytes memory eip3009Sig = _signReceiveWithAuthorization(
            customerPk, customer, address(eip3009Auth), downPayment,
            validAfter, validBefore, nonce
        );

        bytes memory downPaymentAuthData = abi.encode(
            validAfter, validBefore, nonce, eip3009Sig
        );

        bytes memory orderSig = _signOrderAuthorization(
            customerPk, merchant, address(eip3009Token), TOTAL_AMOUNT, INSTALLMENTS,
            DOWN_PAYMENT_BPS, INSTALLMENT_PERIOD, GRACE_PERIOD, LATE_FEE_BPS,
            address(eip3009Auth), address(allowanceAuth),
            manager.authorizationNonce(customer), validBefore
        );

        // Warp past validBefore
        vm.warp(validBefore + 1);

        vm.prank(merchant);
        vm.expectRevert(); // Authorization expired
        manager.createOrder(
            customer, address(eip3009Token), TOTAL_AMOUNT, INSTALLMENTS,
            DOWN_PAYMENT_BPS, INSTALLMENT_PERIOD, GRACE_PERIOD, LATE_FEE_BPS,
            address(eip3009Auth), address(allowanceAuth),
            validBefore + 2 hours, // extend order deadline but auth is expired
            orderSig,
            downPaymentAuthData
        );
    }

    function test_replayAuthorization_reverts() public {
        uint256 downPayment = TOTAL_AMOUNT * DOWN_PAYMENT_BPS / 10000;
        uint256 validAfter = 0;
        uint256 validBefore = block.timestamp + 1 hours;
        bytes32 nonce = keccak256(abi.encode(customer, block.timestamp, "replay"));

        bytes memory eip3009Sig = _signReceiveWithAuthorization(
            customerPk, customer, address(eip3009Auth), downPayment,
            validAfter, validBefore, nonce
        );

        bytes memory downPaymentAuthData = abi.encode(
            validAfter, validBefore, nonce, eip3009Sig
        );

        bytes memory orderSig = _signOrderAuthorization(
            customerPk, merchant, address(eip3009Token), TOTAL_AMOUNT, INSTALLMENTS,
            DOWN_PAYMENT_BPS, INSTALLMENT_PERIOD, GRACE_PERIOD, LATE_FEE_BPS,
            address(eip3009Auth), address(allowanceAuth),
            manager.authorizationNonce(customer), validBefore
        );

        // First order succeeds
        vm.prank(merchant);
        manager.createOrder(
            customer, address(eip3009Token), TOTAL_AMOUNT, INSTALLMENTS,
            DOWN_PAYMENT_BPS, INSTALLMENT_PERIOD, GRACE_PERIOD, LATE_FEE_BPS,
            address(eip3009Auth), address(allowanceAuth),
            validBefore, orderSig, downPaymentAuthData
        );

        // Create a new order signature (nonce incremented)
        bytes memory orderSig2 = _signOrderAuthorization(
            customerPk, merchant, address(eip3009Token), TOTAL_AMOUNT, INSTALLMENTS,
            DOWN_PAYMENT_BPS, INSTALLMENT_PERIOD, GRACE_PERIOD, LATE_FEE_BPS,
            address(eip3009Auth), address(allowanceAuth),
            manager.authorizationNonce(customer), validBefore
        );

        // Try to replay the same EIP-3009 authorization — should fail
        vm.prank(merchant);
        vm.expectRevert(); // Nonce already used
        manager.createOrder(
            customer, address(eip3009Token), TOTAL_AMOUNT, INSTALLMENTS,
            DOWN_PAYMENT_BPS, INSTALLMENT_PERIOD, GRACE_PERIOD, LATE_FEE_BPS,
            address(eip3009Auth), address(allowanceAuth),
            validBefore, orderSig2, downPaymentAuthData
        );
    }

    function test_completeOrderFlow_EIP3009ThenAllowance() public {
        orderId = _createOrderWithEIP3009();

        // Collect all installments
        uint256 startTime = block.timestamp;
        for (uint8 i = 0; i < INSTALLMENTS; i++) {
            vm.warp(startTime + INSTALLMENT_PERIOD * (i + 1));
            vm.prank(merchant);
            manager.collectInstallment(orderId, "");
        }

        IBNPL.Order memory o = manager.getOrder(orderId);
        assertEq(uint8(o.status), uint8(IBNPL.OrderStatus.Completed), "should be completed");
        assertEq(o.paidAmount, TOTAL_AMOUNT, "total paid should equal totalAmount");
    }
}
