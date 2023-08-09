trait Filter<T> {
    fn filter(&self, x: &T) -> bool;
}

trait Filterable: Iterator + Sized {
    fn filter<F: Filter<Self::Item>>(self, f: F) -> Filtered<Self, F>;
}

impl<T: Iterator> Filterable for T {
    fn filter<F: Filter<Self::Item>>(self, f: F) -> Filtered<Self, F> {
        Filtered::new(self, f)
    }
}

struct Filtered<T: Iterator, F: Filter<T::Item>> {
    inner_iterator: T,
    f: F,
}

impl<T: Iterator, F: Filter<T::Item>> Filtered<T, F> {
    fn new(inner_iterator: T, f: F) -> Self {
        Filtered { inner_iterator, f }
    }
}

impl<T: Iterator, F: Filter<T::Item>> Iterator for Filtered<T, F> {
    type Item = T::Item;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            match self.inner_iterator.next() {
                Some(x) => {
                    if self.f.filter(&x) {
                        return Some(x);
                    } else {
                        continue;
                    }
                },
                None => {
                    return None;
                }
            }
        }
    }
}

pub struct Pairs<T: Iterator> {
    inner_iterator: T,
    last: Option<T::Item>,
}

impl<T: Iterator> Pairs<T> {
    pub fn new(mut inner_iterator: T) -> Self {
        let last = inner_iterator.next();
        Pairs {
            inner_iterator,
            last,
        }
    }
}

use std::mem::swap;

impl<T: Iterator> Iterator for Pairs<T>
where
    <T as Iterator>::Item: Copy,
{
    type Item = (T::Item, T::Item);

    fn next(&mut self) -> Option<Self::Item> {
        let current = self.inner_iterator.next();
        let mut last = current;
        swap(&mut last, &mut self.last);
        match (last, current) {
            (Some(last), Some(current)) => {
                Some((last, current))
            },
            _ => { None }
        }
    }
}

pub trait IntoPairs<T: Iterator> {
    fn pairs(self) -> Pairs<T>;
}

impl<T: Iterator> IntoPairs<T> for T {
    fn pairs(self) -> Pairs<T> { Pairs::new(self) }
}

#[cfg(test)]
mod tests {
    use super::IntoPairs;
    #[test]
    fn test_pairs() {
        let xs = [1, 2, 3, 4];

        let mut pairs = xs.iter().pairs();

        assert_eq!((&1, &2), pairs.next().expect("Some"));
        assert_eq!((&2, &3), pairs.next().expect("Some"));
        assert_eq!((&3, &4), pairs.next().expect("Some"));

        assert_eq!(None, pairs.next());
    }
}
