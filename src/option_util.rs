use serde::de::{Deserializer, Error as _};
use serde::{Deserialize, Serialize};
use serde_yaml::Value;

// The three wrappers below serialise untagged but deserialise by hand.
//
// Derived as `#[serde(untagged)]`, each tried its variants in order and, when
// none matched, discarded every variant's error for "data did not match any
// variant of untagged enum NoneOrSome". Almost every nested option sits under
// one of them, so a misspelled value three levels into a config file was
// reported as that and nothing else. These keep the derived order and the
// derived set of accepted inputs exactly, and differ only in what a refusal
// says: the error of the variant the input's shape was meant for -- the
// single item's for a lone value, the list's for a list. The input is
// buffered as a YAML `Value`, as the untagged derive buffered it, and as the
// chain-hop deserialisers in `config::types::rules` already do.

#[derive(Default, Debug, Clone, Serialize)]
#[serde(untagged)]
pub enum NoneOrOne<T> {
    #[default]
    Unspecified,
    None,
    One(T),
}

impl<'de, T: Deserialize<'de>> Deserialize<'de> for NoneOrOne<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        // null is `None`; anything else is the item, with the item's own error.
        match Option::<T>::deserialize(deserializer)? {
            None => Ok(NoneOrOne::None),
            Some(item) => Ok(NoneOrOne::One(item)),
        }
    }
}

impl<T> NoneOrOne<T> {
    pub fn is_unspecified(&self) -> bool {
        matches!(self, NoneOrOne::Unspecified)
    }

    pub fn into_option(self) -> Option<T> {
        match self {
            NoneOrOne::One(item) => Some(item),
            _ => None,
        }
    }

    // Used on non-Linux platforms (macOS, Windows, iOS) for bind_interface validation
    #[allow(dead_code)]
    pub fn is_one(&self) -> bool {
        matches!(self, NoneOrOne::One(_))
    }
}

#[derive(Default, Debug, Clone, Serialize)]
#[serde(untagged)]
pub enum NoneOrSome<T> {
    #[default]
    Unspecified,
    None,
    One(T),
    Some(Vec<T>),
}

impl<'de, T: Deserialize<'de>> Deserialize<'de> for NoneOrSome<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = Value::deserialize(deserializer)?;
        if value.is_null() {
            return Ok(NoneOrSome::None);
        }
        one_then_list(value)
            .map(|parsed| match parsed {
                Parsed::One(item) => NoneOrSome::One(item),
                Parsed::List(items) => NoneOrSome::Some(items),
            })
            .map_err(D::Error::custom)
    }
}

enum Parsed<T> {
    One(T),
    List(Vec<T>),
}

/// The item first, as the untagged derive tried it, then a list of items.
///
/// The order matters and is kept: some items, a `ClientChain` among them,
/// accept a list themselves, and for those a list is one item rather than
/// several. When both fail, a list reports the list's error and anything
/// else the item's.
fn one_then_list<'de, T: Deserialize<'de>>(value: Value) -> Result<Parsed<T>, serde_yaml::Error> {
    let one = match T::deserialize(value.clone()) {
        Ok(item) => return Ok(Parsed::One(item)),
        Err(e) => e,
    };
    if value.is_sequence() {
        return Vec::<T>::deserialize(value).map(Parsed::List);
    }
    Err(one)
}

impl<T> NoneOrSome<T> {
    pub fn is_unspecified(&self) -> bool {
        matches!(self, NoneOrSome::Unspecified)
    }

    pub fn len(&self) -> usize {
        match self {
            NoneOrSome::Unspecified => 0,
            NoneOrSome::None => 0,
            NoneOrSome::One(_) => 1,
            NoneOrSome::Some(v) => v.len(),
        }
    }

    pub fn into_vec(self) -> Vec<T> {
        match self {
            NoneOrSome::Unspecified | NoneOrSome::None => vec![],
            NoneOrSome::One(item) => vec![item],
            NoneOrSome::Some(v) => v,
        }
    }

    pub fn into_iter(self) -> Box<dyn Iterator<Item = T> + Send>
    where
        T: Send + 'static,
    {
        match self {
            NoneOrSome::Unspecified | NoneOrSome::None => Box::new(std::iter::empty()),
            NoneOrSome::One(item) => Box::new(SingleItemIter(Some(item))),
            NoneOrSome::Some(v) => Box::new(v.into_iter()),
        }
    }

    pub fn iter<'a>(&'a self) -> Box<dyn Iterator<Item = &'a T> + Send + 'a>
    where
        T: Sync,
    {
        match self {
            NoneOrSome::Unspecified | NoneOrSome::None => Box::new(std::iter::empty()),
            NoneOrSome::One(item) => Box::new(SingleItemIter(Some(item))),
            NoneOrSome::Some(v) => Box::new(v.iter()),
        }
    }

    pub fn iter_mut<'a>(&'a mut self) -> Box<dyn Iterator<Item = &'a mut T> + Send + 'a>
    where
        T: Send,
    {
        match self {
            NoneOrSome::Unspecified | NoneOrSome::None => Box::new(std::iter::empty()),
            NoneOrSome::One(item) => Box::new(SingleItemIter(Some(item))),
            NoneOrSome::Some(v) => Box::new(v.iter_mut()),
        }
    }

    pub fn is_empty(&self) -> bool {
        match self {
            NoneOrSome::Unspecified => true,
            NoneOrSome::None => true,
            NoneOrSome::One(_) => false,
            NoneOrSome::Some(v) => v.is_empty(),
        }
    }

    pub fn map<F, U>(self, mut f: F) -> NoneOrSome<U>
    where
        F: FnMut(T) -> U,
    {
        match self {
            NoneOrSome::Unspecified => NoneOrSome::Unspecified,
            NoneOrSome::None => NoneOrSome::None,
            NoneOrSome::One(item) => NoneOrSome::One(f(item)),
            NoneOrSome::Some(v) => NoneOrSome::Some(v.into_iter().map(f).collect()),
        }
    }

    pub fn _filter<F>(self, f: F) -> Self
    where
        F: Fn(&T) -> bool,
    {
        match self {
            NoneOrSome::Unspecified => NoneOrSome::Unspecified,
            NoneOrSome::None => NoneOrSome::None,
            NoneOrSome::One(item) => {
                if f(&item) {
                    NoneOrSome::One(item)
                } else {
                    NoneOrSome::None
                }
            }
            NoneOrSome::Some(v) => {
                let filtered: Vec<T> = v.into_iter().filter(f).collect();
                if filtered.is_empty() {
                    NoneOrSome::None
                } else {
                    NoneOrSome::Some(filtered)
                }
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(untagged)]
pub enum OneOrSome<T> {
    One(T),
    Some(Vec<T>),
}

impl<'de, T: Deserialize<'de>> Deserialize<'de> for OneOrSome<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = Value::deserialize(deserializer)?;
        match one_then_list(value).map_err(D::Error::custom)? {
            Parsed::One(item) => Ok(OneOrSome::One(item)),
            Parsed::List(items) if items.is_empty() => Err(D::Error::invalid_value(
                serde::de::Unexpected::Other("empty"),
                &"need at least one element",
            )),
            Parsed::List(items) => Ok(OneOrSome::Some(items)),
        }
    }
}

impl<T> OneOrSome<T> {
    #[cfg(test)]
    pub fn len(&self) -> usize {
        match self {
            OneOrSome::One(_) => 1,
            OneOrSome::Some(v) => v.len(),
        }
    }

    pub fn into_vec(self) -> Vec<T> {
        match self {
            OneOrSome::One(item) => vec![item],
            OneOrSome::Some(v) => v,
        }
    }

    pub fn iter<'a>(&'a self) -> Box<dyn Iterator<Item = &'a T> + Send + 'a>
    where
        T: Sync,
    {
        match self {
            OneOrSome::One(item) => Box::new(SingleItemIter(Some(item))),
            OneOrSome::Some(v) => Box::new(v.iter()),
        }
    }

    pub fn iter_mut<'a>(&'a mut self) -> Box<dyn Iterator<Item = &'a mut T> + Send + 'a>
    where
        T: Send,
    {
        match self {
            OneOrSome::One(item) => Box::new(SingleItemIter(Some(item))),
            OneOrSome::Some(v) => Box::new(v.iter_mut()),
        }
    }

    pub fn _contains(&self, x: &T) -> bool
    where
        T: PartialEq,
    {
        match self {
            OneOrSome::One(item) => item == x,
            OneOrSome::Some(v) => v.contains(x),
        }
    }
}

struct SingleItemIter<T>(Option<T>);

impl<T> Iterator for SingleItemIter<T> {
    type Item = T;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.take()
    }
}

impl<T> TryFrom<Vec<T>> for OneOrSome<T> {
    type Error = std::io::Error;
    fn try_from(vec: Vec<T>) -> std::io::Result<Self> {
        match vec.len() {
            0 => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Cannot create OneOrSome from empty vector",
            )),
            1 => Ok(OneOrSome::One(vec.into_iter().next().unwrap())),
            _ => Ok(OneOrSome::Some(vec)),
        }
    }
}
