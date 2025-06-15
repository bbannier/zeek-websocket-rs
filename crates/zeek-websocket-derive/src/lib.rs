use proc_macro_error2::{abort, proc_macro_error};
use proc_macro2::TokenStream;
use quote::{format_ident, quote};
use syn::{
    Data, DeriveInput, Field, Fields, Ident, ItemFn, parse::Parse, parse_macro_input,
    spanned::Spanned,
};

/// Derive macro to convert a type from and to a `zeek_websocket_types::Value`.
///
/// ```
/// # use zeek_websocket_derive::ZeekType;
/// # use zeek_websocket_types::Value;
/// #[derive(ZeekType)]
/// struct Record {
///     a: String,
///     b: u64,
/// }
///
/// let r = Record { a: "hello".to_string(), b: 1024 };
/// let value = Value::from(r);
/// ```
#[proc_macro_error]
#[proc_macro_derive(ZeekType)]
pub fn derive(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let ast = parse_macro_input!(input as DeriveInput);

    let name = &ast.ident;

    let Data::Struct(struct_) = &ast.data else {
        abort!(ast.span(), "only structs can derive ZeekType");
    };

    let Fields::Named(fields) = &struct_.fields else {
        abort!(
            ast.span(),
            "only structs with named fields can derive ZeekType"
        );
    };
    let fields: Vec<_> = fields.named.iter().cloned().collect();

    let value_from = impl_value_from(name, &fields);
    let from_value = impl_from_value(name, &fields);

    quote! {
        #value_from

        #from_value
    }
    .into()
}

fn impl_value_from(name: &Ident, fields: &[Field]) -> TokenStream {
    let fields = fields.iter().map(|f| {
        let name = &f.ident;
        quote! { ::zeek_websocket_types::Value::from(value.#name) }
    });

    quote! {
        impl From<#name> for ::zeek_websocket_types::Value {
            fn from(value: #name) -> Self {
                Self::from(::std::vec::Vec::<::zeek_websocket_types::Value>::from([#(#fields), *]))
            }
        }
    }
}

fn impl_from_value(name: &Ident, fields: &[Field]) -> TokenStream {
    let xs = format_ident!("__zeek_websocket_derive__impl_from_value_{name}");

    // Validate that all fields are named so we can cleanly unwrap below.
    if fields.iter().any(|f| f.ident.is_none()) {
        abort!(name.span(), "unnamed fields are unsupported");
    }

    let fields = fields.iter().map(|f| {
        let field_name = f.ident.as_ref().unwrap();

        (
            field_name.clone(),
            quote! {

            let #field_name = #xs
                .next()
                .ok_or(::zeek_websocket_types::ConversionError::MismatchedTypes)?
                .try_into()?;
            },
        )
    });

    let (names, inits): (Vec<_>, Vec<_>) = fields.unzip();

    quote! {
        impl TryFrom<::zeek_websocket_types::Value> for #name {
            type Error = ::zeek_websocket_types::ConversionError;

            fn try_from(value: ::zeek_websocket_types::Value) -> Result<Self, Self::Error> {
                #[allow(non_snake_case)]
                let ::zeek_websocket_types::Value::Vector(#xs) = value else {
                    return Err(::zeek_websocket_types::ConversionError::MismatchedTypes);
                };
                let mut #xs = #xs.into_iter();

                #(#inits)*

                Ok(#name { #(#names),* })
            }
        }
    }
}

/// Attribute to automatically generate Zeek event handlers.
#[proc_macro_error]
#[proc_macro_attribute]
pub fn zeek_event(
    attr: proc_macro::TokenStream,
    item: proc_macro::TokenStream,
) -> proc_macro::TokenStream {
    let item = parse_macro_input!(item as ItemFn);

    let args = match syn::parse::<Args>(attr.clone()) {
        Ok(xs) => xs,
        Err(e) => abort!(e.span(), "unexpected argument"),
    };

    let handler_name = args.name;

    let sig = &item.sig;

    let name = &sig.ident;
    if name == &handler_name {
        abort!(
            handler_name.span(),
            "handler name cannot be identical to function name"
        );
    }

    let num_expected_args = sig.inputs.len();

    let converted_args = TokenStream::from_iter((0..num_expected_args).map(|_| {
        quote! {
            #[allow(clippy::unwrap_used)]
            ::std::convert::TryInto::try_into(args.next().unwrap())?,
        }
    }));

    let doc = format!("Automatically generated event handler wrapper for '{name}'.");

    quote! {
        #item

        #[doc= #doc]
        fn #handler_name(args: ::zeek_websocket_types::Value) -> ::std::result::Result<(), ::zeek_websocket_types::ConversionError> {
            use ::zeek_websocket_types::{ConversionError, Value};

            let Value::Vector(args) = args else {
                return Err(ConversionError::MismatchedTypes);
            };

            // Check that number of entries matches up with argument count.
            let num_provided_args = args.len();
            if num_provided_args != #num_expected_args {
                return Err(ConversionError::MismatchedSignature(
                        #num_expected_args,
                        num_provided_args,
                ));
            }

            let mut args = args.into_iter();

            Ok(#name(#converted_args))
        }
    }
    .into()
}

#[derive(Debug)]
struct Args {
    name: Ident,
}

impl Parse for Args {
    fn parse(input: syn::parse::ParseStream) -> syn::Result<Self> {
        Ok(Self {
            name: input.parse()?,
        })
    }
}
