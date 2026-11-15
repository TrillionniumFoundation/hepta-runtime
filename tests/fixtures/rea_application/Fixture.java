// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
package org.hepta;
public final class Fixture {
    private Fixture() {}
    public static void main(String[] arguments) {
        System.out.println("Owned fixture: never executed by the application inspector");
    }
}
