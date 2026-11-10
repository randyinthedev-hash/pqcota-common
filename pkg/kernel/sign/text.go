// SPDX-FileCopyrightText: 2026 Great Honor <randyinthedev@gmail.com>
// SPDX-License-Identifier: Apache-2.0

package sign

import (
	"errors"
	"fmt"
	"strings"

	provisioningv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/provisioning/v1"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// ErrNUL — 계획의 문자열에 NUL이 있다. [errors.Is]로 가를 수 있게 공개한다.
var ErrNUL = errors.New("the plan contains a NUL character")

// CheckPlanText — 계획의 모든 문자열에 NUL이 없는지 본다. 서명을 만들기 전([SignApproval])과 검증하기
// 전([VerifyApprovals])에, 그리고 실행 근거를 판정할 때 **이 함수 하나로** 본다.
//
// [CanonicalPlan]은 필드마다 NUL 하나로 끊고 길이를 붙이지 않는다. 그래서 값 속의 NUL이 경계와 구별되지
// 않아, 서로 다른 계획이 같은 정규형이 될 수 있었다(예: provider_choice="BC\0X"·config_artifact="Y"와
// provider_choice="BC"·config_artifact="X\0Y"). 한 계획의 승인이 다른 계획에서 통과했다. v0.10.6까지다.
//
// 지우거나 바꾸지 않고 **거부한다.** 고쳐서 받으면 승인자가 본 것과 서명한 것이 다시 갈라진다.
// 정규형이 쓰는 필드를 손으로 나열하지 않고 계획 전체의 문자열(중첩·반복·oneof·map)을 훑는다. 그래서 현재
// 계약의 문자열 필드는 모두 본다. 새 문자열 필드도 따라 보지만, 그것이 이 검사로 충분하다는 보증은 아니다 —
// bytes처럼 이 함수가 보지 않는 꼴이 정규형에 들어가거나 정규형의 짜임이 바뀌면, 그때 이 검사와 시험을 함께 고친다.
// 정규형에 없는 approval_signatures도 함께 본다. NUL이 든 승인 서명은 어차피 맞는 꼴이 아니다.
func CheckPlanText(p *provisioningv1.FinalizedPlan) error {
	if p == nil {
		return nil
	}
	return checkText(p.ProtoReflect(), "")
}

func checkText(m protoreflect.Message, path string) error {
	var err error
	m.Range(func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		name := string(fd.Name())
		if path != "" {
			name = path + "." + name
		}
		switch {
		case fd.IsList():
			l := v.List()
			for i := 0; i < l.Len() && err == nil; i++ {
				err = checkValue(fd, l.Get(i), fmt.Sprintf("%s[%d]", name, i))
			}
		case fd.IsMap():
			v.Map().Range(func(k protoreflect.MapKey, mv protoreflect.Value) bool {
				if strings.ContainsRune(k.String(), 0) {
					err = fmt.Errorf("%w in a key of %s", ErrNUL, name)
					return false
				}
				err = checkValue(fd.MapValue(), mv, name+"["+k.String()+"]")
				return err == nil
			})
		default:
			err = checkValue(fd, v, name)
		}
		return err == nil
	})
	return err
}

func checkValue(fd protoreflect.FieldDescriptor, v protoreflect.Value, path string) error {
	switch fd.Kind() {
	case protoreflect.StringKind:
		if strings.ContainsRune(v.String(), 0) {
			return fmt.Errorf("%w in %s — its canonical form would be ambiguous, so it cannot be approved or executed", ErrNUL, path)
		}
	case protoreflect.MessageKind, protoreflect.GroupKind:
		return checkText(v.Message(), path)
	}
	return nil
}
