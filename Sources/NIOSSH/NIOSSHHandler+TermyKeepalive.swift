import NIOCore

extension NIOSSHHandler {
    public func sendOpenSSHKeepalive(promise: EventLoopPromise<Void>?) {
        let inner: EventLoopPromise<ByteBuffer?>?
        if let outer = promise {
            let p = outer.futureResult.eventLoop.makePromise(of: ByteBuffer?.self)
            p.futureResult.whenComplete { result in
                switch result {
                case .success:
                    outer.succeed(())
                case .failure(let error):
                    if let nioError = error as? NIOSSHError, nioError.type == .globalRequestRefused {
                        outer.succeed(())
                    } else {
                        outer.fail(error)
                    }
                }
            }
            inner = p
        } else {
            inner = nil
        }

        let message = SSHMessage.GlobalRequestMessage(
            wantReply: true,
            type: .unknown("keepalive@openssh.com", ByteBuffer())
        )
        self.sendGlobalRequestMessage(message, promise: inner)
    }
}
