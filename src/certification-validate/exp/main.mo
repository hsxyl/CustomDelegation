import C "mo:base/CertifiedData";
import T "mo:base/Text";

actor {

    public func set(arg : Text) : async(){
        C.set(T.encodeUtf8(arg))
    };

    public query({caller}) func get() : async ?Blob{
        C.getCertificate()
    };

};
