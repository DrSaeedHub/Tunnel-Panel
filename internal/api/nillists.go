package api

import "reflect"

// A nil slice marshals to JSON null, and null is not a list.
//
// Three separate defects in this panel were the same sentence: the metrics
// snapshot sent "cpu": null, the forwarding rules sent "allowed_sources": null,
// and in both cases the interface called .map on it and the whole page went
// down. Each was fixed where it was found. This is the general form, applied
// once at the only place a response body is written.
//
// The rule is the field's own tag. A slice declared without omitempty is
// promised to the client unconditionally, so it has to arrive as an array —
// empty when there is nothing in it. A slice declared *with* omitempty is
// saying its absence is meaningful, and normalising it would turn "there is no
// such thing here" into "here is an empty thing", which is a different claim.
// So omitempty is left strictly alone.
//
// This runs on the value about to be marshalled, so it cannot be bypassed by a
// handler that forgets to normalise, and a new response struct gets the
// behaviour without anyone remembering to ask for it.

// normaliseNilLists returns the value to marshal, with nil slices replaced by
// empty ones wherever the field is not tagged omitempty.
//
// Handlers pass structs by value, and a struct reached through reflect.ValueOf
// is not addressable, so its fields cannot be set. Those are copied into an
// addressable location first and the copy is returned — which is why the result
// must be used rather than relying on mutation.
func normaliseNilLists(v any) any {
	if v == nil {
		return v
	}
	seen := make(map[uintptr]bool)
	rv := reflect.ValueOf(v)

	switch rv.Kind() {
	case reflect.Pointer, reflect.Map:
		// Reference types: the caller's own value is reached, so in-place works.
		normaliseValue(rv, false, seen)
		return v
	case reflect.Slice:
		if rv.IsNil() {
			return reflect.MakeSlice(rv.Type(), 0, 0).Interface()
		}
		normaliseValue(rv, false, seen)
		return v
	default:
		copied := reflect.New(rv.Type()).Elem()
		copied.Set(rv)
		normaliseValue(copied, false, seen)
		return copied.Interface()
	}
}

// normaliseValue walks a value. omitempty says whether the field this value
// came from was tagged omitempty, in which case a nil slice is left as it is.
//
// seen guards against a structure that points at itself. Response payloads are
// trees today, but a cycle here would be an infinite loop in the response path,
// which is a much worse failure than the one being fixed.
func normaliseValue(v reflect.Value, omitempty bool, seen map[uintptr]bool) {
	switch v.Kind() {
	case reflect.Pointer, reflect.Interface:
		if v.IsNil() {
			return
		}
		if v.Kind() == reflect.Pointer {
			if seen[v.Pointer()] {
				return
			}
			seen[v.Pointer()] = true
		}
		normaliseValue(v.Elem(), omitempty, seen)

	case reflect.Slice:
		if v.IsNil() {
			// Only a settable slice can be replaced. A slice reached through an
			// unexported field or a non-addressable copy is left alone rather
			// than panicking.
			if !omitempty && v.CanSet() {
				v.Set(reflect.MakeSlice(v.Type(), 0, 0))
			}
			return
		}
		for i := 0; i < v.Len(); i++ {
			normaliseValue(v.Index(i), false, seen)
		}

	case reflect.Map:
		if v.IsNil() {
			return
		}
		for _, key := range v.MapKeys() {
			element := v.MapIndex(key)
			// Map values are not addressable, so an element that needs changing
			// has to be copied, normalised and written back.
			copied := reflect.New(element.Type()).Elem()
			copied.Set(element)
			normaliseValue(copied, false, seen)
			v.SetMapIndex(key, copied)
		}

	case reflect.Struct:
		t := v.Type()
		for i := 0; i < v.NumField(); i++ {
			field := t.Field(i)
			if !field.IsExported() {
				continue
			}
			tag := field.Tag.Get("json")
			if tag == "-" {
				continue
			}
			normaliseValue(v.Field(i), hasOmitempty(tag), seen)
		}
	}
}

// hasOmitempty reports whether a json struct tag carries the omitempty option.
func hasOmitempty(tag string) bool {
	for len(tag) > 0 {
		var part string
		if i := indexByte(tag, ','); i >= 0 {
			part, tag = tag[:i], tag[i+1:]
		} else {
			part, tag = tag, ""
		}
		if part == "omitempty" {
			return true
		}
	}
	return false
}

func indexByte(s string, c byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return i
		}
	}
	return -1
}
