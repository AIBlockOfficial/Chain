/// Generate an enum to be used as an error type.
///
/// This will automatically generate the enum, but also implement `Display` with given format
/// strings and optionally indicate the source error for errors which wrap another error.
///
/// Example usage:
/// ```ignore
/// make_error_type!(pub MyError {
///     Unknown; "Unknown error",
///     IncorrectLength(length: usize); "Incorrect length {length}, expected 123",
///     InvalidHexData(source: hex::FromHexError); "Cannot convert hex string: {source}"; source,
/// });
/// ```
macro_rules! make_error_type {
    (@fmt_args $tname:ident) => { Self::$tname };
    (@fmt_args $tname:ident ( $($targn:ident),+ )) => { Self::$tname($($targn),+) };

    (@fmt_source) => { None };
    (@fmt_source $sourcen:expr) => { Some($sourcen) };

    ($(#[derive( $($derive:ident),+ )])?  $vis:vis $name:ident {
        $( $tname:ident $(( $($targn:ident : $targ:ty),+ ))? ; $tmsg:literal $(; $sourcen:expr )?),+ $(,)?
    }) => {
        $( #[derive( $($derive),+ )] )?
        #[derive(Clone, std::fmt::Debug)]
        $vis enum $name {
            $( $tname $(( $($targ),+ ))? ),+
        }

        impl std::error::Error for $name {
            fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
                match self {
                    $(
                        make_error_type!(@fmt_args $tname $(( $($targn),+ ))?)
                        =>
                        make_error_type!(@fmt_source $($sourcen)?)
                    ),+
                }
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, _f: &mut std::fmt::Formatter) -> std::fmt::Result {
                match self {
                    $(
                        make_error_type!(@fmt_args $tname $(( $($targn),+ ))?)
                        =>
                        write!(_f, $tmsg)
                    ),+
                }
            }
        }
    };
}
