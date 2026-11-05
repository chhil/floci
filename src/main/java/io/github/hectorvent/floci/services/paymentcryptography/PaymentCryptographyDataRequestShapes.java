package io.github.hectorvent.floci.services.paymentcryptography;

import com.fasterxml.jackson.databind.JsonNode;
import io.github.hectorvent.floci.core.common.AwsException;
import io.github.hectorvent.floci.core.common.RequestConstraintCheck;

import java.util.List;

/**
 * Checks a Payment Cryptography data plane request against the constraints vendored in
 * {@code aws/payment-cryptography-data-request-shapes.json} by
 * {@code tools/aws/regen_payment_cryptography_data_shapes.py}.
 *
 * <p>The patterns are what settle which key a request may name: {@code KeyIdentifier} takes the ARN
 * of a key, the ARN of an alias or the name of an alias, and the identifier of a key on its own
 * names none of them. A violation is a {@code ValidationException}, with the member's path from
 * the request's top level.
 *
 * <p>The data plane is a service of its own, so its constraints are vendored in a file of their
 * own and checked here, as the control plane's are.
 */
final class PaymentCryptographyDataRequestShapes {

    private static final RequestConstraintCheck CHECK = RequestConstraintCheck.load(
            "aws/payment-cryptography-data-request-shapes.json",
            "Payment Cryptography data plane request shapes",
            new RequestConstraintCheck.Messages() {
                @Override
                public AwsException type(String path, String type) {
                    return invalid(path, "Member must be a " + type);
                }

                @Override
                public AwsException bounds(String path, String type, Long min, Long max, long size) {
                    String measure = "integer".equals(type) || "long".equals(type) ? "value" : "length";
                    return min != null && size < min
                            ? invalid(path, "Member must have " + measure + " greater than or equal to " + min)
                            : invalid(path, "Member must have " + measure + " less than or equal to " + max);
                }

                @Override
                public AwsException pattern(String path, String pattern) {
                    return invalid(path, "must satisfy regular expression '" + pattern + "'");
                }

                @Override
                public AwsException enumValue(String path, List<String> values) {
                    return invalid(path, "Member must satisfy enum value set: " + values);
                }

                @Override
                public AwsException required(String path) {
                    return invalid(path, "Member must not be null");
                }
            });

    private PaymentCryptographyDataRequestShapes() {
    }

    /**
     * Checks a request of an operation against the constraints the model states for it.
     *
     * @param operation the operation the request is
     * @param request the request
     */
    static void check(String operation, JsonNode request) {
        CHECK.check(operation, request);
    }

    /** The member's path below the operation, with list elements folded into their list. */
    private static AwsException invalid(String path, String rule) {
        int dot = path.indexOf('.');
        String member = (dot < 0 ? "" : path.substring(dot + 1)).replace("[]", "");
        return new AwsException("ValidationException",
                "Invalid parameter at '" + member + "' failed to satisfy constraint: '" + rule + "'", 400);
    }
}
