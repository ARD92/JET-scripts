# Generated by the gRPC Python protocol compiler plugin. DO NOT EDIT!
"""Client and server classes corresponding to protobuf-defined services."""
import grpc

import jnx_firewall_service_pb2 as jnx__firewall__service__pb2


class FirewallStub(object):
    """[brief]: Filter configuration and operational service.
    [detail]: Filter configuration and operational service.
    Filter Service defines a set of simple RPCs to operate upon the various
    components, viz.
    - Filter.
    - Term.
    - Policer.
    - Filter Attachment/Bind Points.
    - Statistics.

    Each of RPCs are named by concatenating the corresponding Filter object and the operation
    to be performed. This give a easy to understand semantics to the RPCs.
    """

    def __init__(self, channel):
        """Constructor.

        Args:
            channel: A grpc.Channel.
        """
        self.FilterAdd = channel.unary_unary(
                '/jnx.jet.firewall.Firewall/FilterAdd',
                request_serializer=jnx__firewall__service__pb2.FilterAddRequest.SerializeToString,
                response_deserializer=jnx__firewall__service__pb2.FilterAddResponse.FromString,
                )
        self.FilterDelete = channel.unary_unary(
                '/jnx.jet.firewall.Firewall/FilterDelete',
                request_serializer=jnx__firewall__service__pb2.FilterDeleteRequest.SerializeToString,
                response_deserializer=jnx__firewall__service__pb2.FilterDeleteResponse.FromString,
                )
        self.FilterModify = channel.unary_unary(
                '/jnx.jet.firewall.Firewall/FilterModify',
                request_serializer=jnx__firewall__service__pb2.FilterModifyRequest.SerializeToString,
                response_deserializer=jnx__firewall__service__pb2.FilterModifyResponse.FromString,
                )
        self.FilterBindAdd = channel.unary_unary(
                '/jnx.jet.firewall.Firewall/FilterBindAdd',
                request_serializer=jnx__firewall__service__pb2.FilterObjBindAddRequest.SerializeToString,
                response_deserializer=jnx__firewall__service__pb2.FilterBindAddResponse.FromString,
                )
        self.FilterBindDelete = channel.unary_unary(
                '/jnx.jet.firewall.Firewall/FilterBindDelete',
                request_serializer=jnx__firewall__service__pb2.FilterObjBindDeleteRequest.SerializeToString,
                response_deserializer=jnx__firewall__service__pb2.FilterBindDeleteResponse.FromString,
                )
        self.PolicerAdd = channel.unary_unary(
                '/jnx.jet.firewall.Firewall/PolicerAdd',
                request_serializer=jnx__firewall__service__pb2.PolicerAddRequest.SerializeToString,
                response_deserializer=jnx__firewall__service__pb2.PolicerAddResponse.FromString,
                )
        self.PolicerModify = channel.unary_unary(
                '/jnx.jet.firewall.Firewall/PolicerModify',
                request_serializer=jnx__firewall__service__pb2.PolicerModifyRequest.SerializeToString,
                response_deserializer=jnx__firewall__service__pb2.PolicerModifyResponse.FromString,
                )
        self.PolicerDelete = channel.unary_unary(
                '/jnx.jet.firewall.Firewall/PolicerDelete',
                request_serializer=jnx__firewall__service__pb2.PolicerDeleteRequest.SerializeToString,
                response_deserializer=jnx__firewall__service__pb2.PolicerDeleteResponse.FromString,
                )
        self.FilterCounterGet = channel.unary_unary(
                '/jnx.jet.firewall.Firewall/FilterCounterGet',
                request_serializer=jnx__firewall__service__pb2.FilterCounterGetRequest.SerializeToString,
                response_deserializer=jnx__firewall__service__pb2.FilterCounterGetResponse.FromString,
                )
        self.PolicerCounterGet = channel.unary_unary(
                '/jnx.jet.firewall.Firewall/PolicerCounterGet',
                request_serializer=jnx__firewall__service__pb2.PolicerCounterGetRequest.SerializeToString,
                response_deserializer=jnx__firewall__service__pb2.PolicerCounterGetResponse.FromString,
                )
        self.FilterCounterSet = channel.unary_unary(
                '/jnx.jet.firewall.Firewall/FilterCounterSet',
                request_serializer=jnx__firewall__service__pb2.FilterCounterSetRequest.SerializeToString,
                response_deserializer=jnx__firewall__service__pb2.FilterCounterSetResponse.FromString,
                )
        self.PolicerCounterSet = channel.unary_unary(
                '/jnx.jet.firewall.Firewall/PolicerCounterSet',
                request_serializer=jnx__firewall__service__pb2.PolicerCounterSetRequest.SerializeToString,
                response_deserializer=jnx__firewall__service__pb2.PolicerCounterSetResponse.FromString,
                )


class FirewallServicer(object):
    """[brief]: Filter configuration and operational service.
    [detail]: Filter configuration and operational service.
    Filter Service defines a set of simple RPCs to operate upon the various
    components, viz.
    - Filter.
    - Term.
    - Policer.
    - Filter Attachment/Bind Points.
    - Statistics.

    Each of RPCs are named by concatenating the corresponding Filter object and the operation
    to be performed. This give a easy to understand semantics to the RPCs.
    """

    def FilterAdd(self, request, context):
        """[brief]: This RPC is used to add Filter onto a JUNOS device
        [detail]: This RPC is used to add complete Filter with provided
        all terms and returns the response with appropriate status.
        """
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def FilterDelete(self, request, context):
        """[brief]: This RPC is used to delete Filter on JUNOS device
        [detail]: This RPC is used to delete complete Filter. Term's are not
        required to be a part of Filter while deleting. Term's are not validated and
        untouched, Even if Term's are existing in Filter delete operation.
        """
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def FilterModify(self, request, context):
        """[brief]: This RPC is to Modify one or more Term's in existing Filter.
        [detail]: Changes an Filter based on the list of Filter Terms provided,
        and returns the result. It is advisable to use this API to for small
        incremental changes. For wholesale changes, it is recommended to use
        TERM_OPERATION_REPLACE for all the Term's required to replace with same
        Term names. For replacing all Terms with new set of Terms, use Term operation as
        TERM_OPERATION_DELETE for existing Terms and TERM_OPERATION_ADD for NEW
        Term entries and prepend to the existing Terms with in Filter.
        """
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def FilterBindAdd(self, request, context):
        """[brief]: This RPC used to Add binding of an Filter with given bind object and return the result.
        [detail]: Binds Filter to the provided bind object if exists in the device
        and provides the result. Note that the device can also have native cli
        Filters configured. Then the order of exection of Filter will follow as
        mentioned here:
        In Ingress direction:
        input_interface-> Client Filter -> CLI Filter -> route_lookup
        In Egress direction:
        route_lookup -> CLI Filter -> Client Filter -> output_interface.
        """
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def FilterBindDelete(self, request, context):
        """[brief]: This RPC Deletes a binding of an Filter with mentioned bind object and return the result.
        [detail]: Deletes a binding of an Filter with mentioned bind object and return the result.
        """
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def PolicerAdd(self, request, context):
        """[brief]: This RPC Adds a policer and returns the result.
        [detail]: This RPC Adds a policer and returns the result.
        """
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def PolicerModify(self, request, context):
        """[brief]: This RPC Modifies the existing policer and returns the result.
        [detail]: This RPC Modifies the existing policer and returns the result.
        """
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def PolicerDelete(self, request, context):
        """[brief]: This RPC deletes the existing policer and returns the result.
        [detail]: This RPC deletes the existing policer and returns the result.
        """
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def FilterCounterGet(self, request, context):
        """[brief]: This RPC is used to get the counter value of specified Filter counter
        [detail]: This RPC is used to get the counter value of specified counter
        in given Filter. Also few points to note with this API. Currently only 1
        counter get is supported.
        This call is going to be blocking for worst case of 10 seconds which is non configurable.
        The counter name is expected to be fully resolved.
        """
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def PolicerCounterGet(self, request, context):
        """[brief]: This RPC is used to get the counter value of specified policer counter of given Filter
        [detail]: This RPC is used to get the counter value of specified policer counter
        in given Filter. Also few points to note with this API. Currently only 1 counter get
        is supported.
        This call is going to be blocking for worst case of 10 seconds which is non configurable.
        The counter name is expected to be fully resolved. For eg. for term specific policer counter
        it is expected to be passed to full counter name as
        <policer_name-term_name> .
        """
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def FilterCounterSet(self, request, context):
        """[brief]: This RPC used to clear filter counter of given Filter.
        [detail]: Clears a particular counter or policer counter whose fully
        qualified name is provided along with associated Filter.
        Few points to note with this API. Currently only 1 counter get is supported.
        The counter name is expected to be fully resolved. For eg. for term specific policer counter
        it is expected to be passed to full counter name as
        <policer_name-term_name> .
        """
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def PolicerCounterSet(self, request, context):
        """[brief]: This RPC used to clear policer counter of given Filter.
        [detail]: Clears a particular policer counter whose fully
        qualified name is provided along with associated.
        Few points to note with this API. Currently only 1 counter get is supported.
        The counter name is expected to be fully resolved. For eg. for term specific policer counter
        it is expected to be passed to full counter name as
        <policer_name-term_name> .
        """
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')


def add_FirewallServicer_to_server(servicer, server):
    rpc_method_handlers = {
            'FilterAdd': grpc.unary_unary_rpc_method_handler(
                    servicer.FilterAdd,
                    request_deserializer=jnx__firewall__service__pb2.FilterAddRequest.FromString,
                    response_serializer=jnx__firewall__service__pb2.FilterAddResponse.SerializeToString,
            ),
            'FilterDelete': grpc.unary_unary_rpc_method_handler(
                    servicer.FilterDelete,
                    request_deserializer=jnx__firewall__service__pb2.FilterDeleteRequest.FromString,
                    response_serializer=jnx__firewall__service__pb2.FilterDeleteResponse.SerializeToString,
            ),
            'FilterModify': grpc.unary_unary_rpc_method_handler(
                    servicer.FilterModify,
                    request_deserializer=jnx__firewall__service__pb2.FilterModifyRequest.FromString,
                    response_serializer=jnx__firewall__service__pb2.FilterModifyResponse.SerializeToString,
            ),
            'FilterBindAdd': grpc.unary_unary_rpc_method_handler(
                    servicer.FilterBindAdd,
                    request_deserializer=jnx__firewall__service__pb2.FilterObjBindAddRequest.FromString,
                    response_serializer=jnx__firewall__service__pb2.FilterBindAddResponse.SerializeToString,
            ),
            'FilterBindDelete': grpc.unary_unary_rpc_method_handler(
                    servicer.FilterBindDelete,
                    request_deserializer=jnx__firewall__service__pb2.FilterObjBindDeleteRequest.FromString,
                    response_serializer=jnx__firewall__service__pb2.FilterBindDeleteResponse.SerializeToString,
            ),
            'PolicerAdd': grpc.unary_unary_rpc_method_handler(
                    servicer.PolicerAdd,
                    request_deserializer=jnx__firewall__service__pb2.PolicerAddRequest.FromString,
                    response_serializer=jnx__firewall__service__pb2.PolicerAddResponse.SerializeToString,
            ),
            'PolicerModify': grpc.unary_unary_rpc_method_handler(
                    servicer.PolicerModify,
                    request_deserializer=jnx__firewall__service__pb2.PolicerModifyRequest.FromString,
                    response_serializer=jnx__firewall__service__pb2.PolicerModifyResponse.SerializeToString,
            ),
            'PolicerDelete': grpc.unary_unary_rpc_method_handler(
                    servicer.PolicerDelete,
                    request_deserializer=jnx__firewall__service__pb2.PolicerDeleteRequest.FromString,
                    response_serializer=jnx__firewall__service__pb2.PolicerDeleteResponse.SerializeToString,
            ),
            'FilterCounterGet': grpc.unary_unary_rpc_method_handler(
                    servicer.FilterCounterGet,
                    request_deserializer=jnx__firewall__service__pb2.FilterCounterGetRequest.FromString,
                    response_serializer=jnx__firewall__service__pb2.FilterCounterGetResponse.SerializeToString,
            ),
            'PolicerCounterGet': grpc.unary_unary_rpc_method_handler(
                    servicer.PolicerCounterGet,
                    request_deserializer=jnx__firewall__service__pb2.PolicerCounterGetRequest.FromString,
                    response_serializer=jnx__firewall__service__pb2.PolicerCounterGetResponse.SerializeToString,
            ),
            'FilterCounterSet': grpc.unary_unary_rpc_method_handler(
                    servicer.FilterCounterSet,
                    request_deserializer=jnx__firewall__service__pb2.FilterCounterSetRequest.FromString,
                    response_serializer=jnx__firewall__service__pb2.FilterCounterSetResponse.SerializeToString,
            ),
            'PolicerCounterSet': grpc.unary_unary_rpc_method_handler(
                    servicer.PolicerCounterSet,
                    request_deserializer=jnx__firewall__service__pb2.PolicerCounterSetRequest.FromString,
                    response_serializer=jnx__firewall__service__pb2.PolicerCounterSetResponse.SerializeToString,
            ),
    }
    generic_handler = grpc.method_handlers_generic_handler(
            'jnx.jet.firewall.Firewall', rpc_method_handlers)
    server.add_generic_rpc_handlers((generic_handler,))


 # This class is part of an EXPERIMENTAL API.
class Firewall(object):
    """[brief]: Filter configuration and operational service.
    [detail]: Filter configuration and operational service.
    Filter Service defines a set of simple RPCs to operate upon the various
    components, viz.
    - Filter.
    - Term.
    - Policer.
    - Filter Attachment/Bind Points.
    - Statistics.

    Each of RPCs are named by concatenating the corresponding Filter object and the operation
    to be performed. This give a easy to understand semantics to the RPCs.
    """

    @staticmethod
    def FilterAdd(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(request, target, '/jnx.jet.firewall.Firewall/FilterAdd',
            jnx__firewall__service__pb2.FilterAddRequest.SerializeToString,
            jnx__firewall__service__pb2.FilterAddResponse.FromString,
            options, channel_credentials,
            insecure, call_credentials, compression, wait_for_ready, timeout, metadata)

    @staticmethod
    def FilterDelete(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(request, target, '/jnx.jet.firewall.Firewall/FilterDelete',
            jnx__firewall__service__pb2.FilterDeleteRequest.SerializeToString,
            jnx__firewall__service__pb2.FilterDeleteResponse.FromString,
            options, channel_credentials,
            insecure, call_credentials, compression, wait_for_ready, timeout, metadata)

    @staticmethod
    def FilterModify(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(request, target, '/jnx.jet.firewall.Firewall/FilterModify',
            jnx__firewall__service__pb2.FilterModifyRequest.SerializeToString,
            jnx__firewall__service__pb2.FilterModifyResponse.FromString,
            options, channel_credentials,
            insecure, call_credentials, compression, wait_for_ready, timeout, metadata)

    @staticmethod
    def FilterBindAdd(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(request, target, '/jnx.jet.firewall.Firewall/FilterBindAdd',
            jnx__firewall__service__pb2.FilterObjBindAddRequest.SerializeToString,
            jnx__firewall__service__pb2.FilterBindAddResponse.FromString,
            options, channel_credentials,
            insecure, call_credentials, compression, wait_for_ready, timeout, metadata)

    @staticmethod
    def FilterBindDelete(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(request, target, '/jnx.jet.firewall.Firewall/FilterBindDelete',
            jnx__firewall__service__pb2.FilterObjBindDeleteRequest.SerializeToString,
            jnx__firewall__service__pb2.FilterBindDeleteResponse.FromString,
            options, channel_credentials,
            insecure, call_credentials, compression, wait_for_ready, timeout, metadata)

    @staticmethod
    def PolicerAdd(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(request, target, '/jnx.jet.firewall.Firewall/PolicerAdd',
            jnx__firewall__service__pb2.PolicerAddRequest.SerializeToString,
            jnx__firewall__service__pb2.PolicerAddResponse.FromString,
            options, channel_credentials,
            insecure, call_credentials, compression, wait_for_ready, timeout, metadata)

    @staticmethod
    def PolicerModify(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(request, target, '/jnx.jet.firewall.Firewall/PolicerModify',
            jnx__firewall__service__pb2.PolicerModifyRequest.SerializeToString,
            jnx__firewall__service__pb2.PolicerModifyResponse.FromString,
            options, channel_credentials,
            insecure, call_credentials, compression, wait_for_ready, timeout, metadata)

    @staticmethod
    def PolicerDelete(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(request, target, '/jnx.jet.firewall.Firewall/PolicerDelete',
            jnx__firewall__service__pb2.PolicerDeleteRequest.SerializeToString,
            jnx__firewall__service__pb2.PolicerDeleteResponse.FromString,
            options, channel_credentials,
            insecure, call_credentials, compression, wait_for_ready, timeout, metadata)

    @staticmethod
    def FilterCounterGet(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(request, target, '/jnx.jet.firewall.Firewall/FilterCounterGet',
            jnx__firewall__service__pb2.FilterCounterGetRequest.SerializeToString,
            jnx__firewall__service__pb2.FilterCounterGetResponse.FromString,
            options, channel_credentials,
            insecure, call_credentials, compression, wait_for_ready, timeout, metadata)

    @staticmethod
    def PolicerCounterGet(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(request, target, '/jnx.jet.firewall.Firewall/PolicerCounterGet',
            jnx__firewall__service__pb2.PolicerCounterGetRequest.SerializeToString,
            jnx__firewall__service__pb2.PolicerCounterGetResponse.FromString,
            options, channel_credentials,
            insecure, call_credentials, compression, wait_for_ready, timeout, metadata)

    @staticmethod
    def FilterCounterSet(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(request, target, '/jnx.jet.firewall.Firewall/FilterCounterSet',
            jnx__firewall__service__pb2.FilterCounterSetRequest.SerializeToString,
            jnx__firewall__service__pb2.FilterCounterSetResponse.FromString,
            options, channel_credentials,
            insecure, call_credentials, compression, wait_for_ready, timeout, metadata)

    @staticmethod
    def PolicerCounterSet(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(request, target, '/jnx.jet.firewall.Firewall/PolicerCounterSet',
            jnx__firewall__service__pb2.PolicerCounterSetRequest.SerializeToString,
            jnx__firewall__service__pb2.PolicerCounterSetResponse.FromString,
            options, channel_credentials,
            insecure, call_credentials, compression, wait_for_ready, timeout, metadata)
